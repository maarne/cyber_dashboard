"""Availability/discovery acceptance tests. All probes/DNS mocked; isolated DB."""
from scratch import test_support

import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from pathlib import Path

os.environ.update(FEATURE_ASSET_PRIORITIZATION='true', FEATURE_ASSET_MONITORING='true', FEATURE_ASSET_DISCOVERY='true',
                  ASSET_PROBE_ALLOWED_CIDRS='192.168.50.0/24,192.168.51.0/24,fc01::/120')

from fastapi.testclient import TestClient
from app import config
from app.database import initialize_database, get_connection
from app.main import app
from app.models.asset_network_schemas import MonitorSettings, DiscoverySettings, CheckRequest, DiscoveryImportRequest
from app.services import auth_service as auth, asset_service as assets, asset_network_service as network
from app.services import asset_network_worker as worker, asset_probe_service as probes, asset_discovery_service as discovery
from app.services.asset_probe_policy import ProbePolicy, ProbePolicyError, hostname
from app.services.audit_service import verify_audit_log_integrity
from app.services.api_token_service import get_api_endpoints_catalog


class AssetNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        password = auth.generate_secure_random_password(18)
        auth.complete_initial_setup('owner', password)
        for role in ('analyst', 'viewer'): auth.create_user(role, password, role)
        cls.actor = {'username': 'owner', 'role': 'admin', 'user_id': auth.get_user_by_username('owner')['id']}
        cls.headers = {role: {'Authorization': 'Bearer ' + auth.create_access_token(name)}
                       for role, name in (('admin', 'owner'), ('analyst', 'analyst'), ('viewer', 'viewer'))}

    def setUp(self):
        test_support.assert_test_database()
        self.guard = patch.object(probes, 'bounded_process', side_effect=AssertionError('Real probes/DNS forbidden in tests'))
        self.guard.start()
        self.own = patch('app.services.asset_probe_policy.self_addresses', return_value=set())
        self.own.start(); worker._stop.clear()
        with get_connection() as conn:
            for table in ('asset_discovery_import_previews', 'asset_discovery_links', 'asset_addresses', 'asset_discovery_observations', 'asset_discovery_candidates',
                          'asset_network_locks', 'asset_network_budget', 'asset_network_jobs', 'asset_monitor_configs', 'asset_discovery_profiles',
                          'asset_assessment_events', 'asset_cve_assessments', 'asset_software', 'asset_tags', 'assets', 'audit_logs'):
                conn.execute(f'DELETE FROM {table}')
            conn.execute('UPDATE asset_inventory_state SET revision=0')
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close(); self.own.stop(); self.guard.stop()

    def request(self, method, path, data=None, role='admin', expected=200):
        response = self.client.request(method, path, headers=self.headers[role], **({'json': data} if data is not None else {}))
        self.assertEqual(response.status_code, expected, response.text)
        self.assertIn('no-store', response.headers['cache-control'])
        return response.json()

    def asset(self, external_id='one'):
        return assets.create_asset({'external_id': external_id, 'name': 'Private test asset'}, self.actor)

    def monitor(self, asset_id, **changes):
        return network.save_monitor(asset_id, MonitorSettings(expected_version=0, target='192.168.50.5', enabled=True, authorized=True,
                                                            **changes), self.actor)

    def profile(self, **changes):
        values = {'name': 'Private lab', 'networks': ['192.168.50.0/30', '192.168.51.0/30'], 'enabled': True, 'authorized': True, **changes}
        return network.save_profile(None, DiscoverySettings(**values), self.actor)

    def enqueue(self, kind, object_id, generation=1):
        return network.request_job(kind, object_id, CheckRequest(expected_generation=generation, idempotency_key='test-request-key'), self.actor)

    def discover(self, profile):
        self.enqueue('discovery', profile['id'])
        job = worker.claim_job()
        with patch.object(probes, 'discover', side_effect=lambda ips, *_args, **_kwargs: [{'address': ip, 'evidence': 'discovery_response'} for ip in ips]):
            worker.execute_job(job)
        return discovery.candidates()['items']

    def test_migration_idempotent_and_no_targets_jobs(self):
        initialize_database(); initialize_database()
        with get_connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0], 3)
            for table in ('asset_monitor_configs', 'asset_discovery_profiles', 'asset_network_jobs'):
                self.assertEqual(conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0], 0)
            self.assertFalse(conn.execute('PRAGMA foreign_key_check').fetchall())

    def test_policy_scope_injection_self_metadata_mixed_dns_and_cardinality(self):
        policy = ProbePolicy()
        self.assertEqual(policy.approve('192.168.50.5'), '192.168.50.5')
        self.assertEqual(policy.approve('::ffff:192.168.50.5'), '192.168.50.5')
        for target in ('127.0.0.1', '169.254.169.254', '168.63.129.16', '100.100.100.200', 'fd00:ec2::254', '8.8.8.8', '0.0.0.0', '224.0.0.1'):
            with self.assertRaises(ProbePolicyError): policy.approve(target)
        for target in ('-oNbad', 'example.com;id', 'http://example.com', '192.168.50.0/24', '127.1', '2130706433', 'fe80::1%eth0'):
            with self.assertRaises(ProbePolicyError): hostname(target)
        with patch('app.services.asset_probe_policy.self_addresses', return_value={ipaddress.ip_address('192.168.50.5')}):
            with self.assertRaises(ProbePolicyError): ProbePolicy().approve('192.168.50.5')
        with patch.object(config, 'ASSET_PROBE_ALLOWED_CIDRS', '192.168.0.0/16'):
            with self.assertRaises(ProbePolicyError): ProbePolicy().targets(['192.168.0.0/16'], [])
        with self.assertRaises(ProbePolicyError): policy.targets(['192.168.0.0/16'], [])
        ips = policy.targets(['192.168.50.0/29', '192.168.50.0/30'], ['192.168.50.1/32'])
        self.assertEqual(len(ips), 5); self.assertNotIn('192.168.50.1', ips)
        with patch.object(probes, 'bounded_process', return_value=(0, b'["192.168.50.5","127.0.0.1"]')):
            with self.assertRaises(ProbePolicyError): probes.resolve('test.example', policy)

    def test_scope_environment_defaults_replacement_and_explicit_empty(self):
        code = """from scratch import test_support
import json
from app import config
print(json.dumps({'scope': config.ASSET_PROBE_ALLOWED_CIDRS,
                  'monitoring': config.FEATURE_ASSET_MONITORING,
                  'discovery': config.FEATURE_ASSET_DISCOVERY}))
"""
        default = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'
        for override, expected in ((None, default), ('', ''), ('192.168.50.0/24', '192.168.50.0/24')):
            with self.subTest(override=override):
                env = dict(os.environ)
                for name in ('ASSET_PROBE_ALLOWED_CIDRS', 'FEATURE_ASSET_MONITORING', 'FEATURE_ASSET_DISCOVERY'):
                    env.pop(name, None)
                if override is not None:
                    env['ASSET_PROBE_ALLOWED_CIDRS'] = override
                result = subprocess.run([sys.executable, '-B', '-c', code], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'scope': expected, 'monitoring': False, 'discovery': False})

    def test_rfc1918_default_scope_preserves_hard_denials_and_opt_in(self):
        with patch.object(config, 'ASSET_PROBE_ALLOWED_CIDRS', config.DEFAULT_ASSET_PROBE_ALLOWED_CIDRS):
            policy = ProbePolicy()
            for ip in ('10.0.0.1', '10.255.255.254', '172.16.0.1', '172.31.255.254', '192.168.0.1', '192.168.255.254', '::ffff:10.1.2.3'):
                self.assertEqual(policy.approve(ip), str(ipaddress.ip_address(ip).ipv4_mapped) if ':' in ip else ip)
            for ip in ('9.255.255.254', '11.0.0.1', '172.15.255.254', '172.32.0.1', '192.167.255.254', '192.169.0.1',
                       '8.8.8.8', '100.64.0.1', '127.0.0.1', '169.254.169.254', '168.63.129.16', '100.100.100.200',
                       '0.0.0.0', '224.0.0.1', 'fc01::1', 'fd00:ec2::254', '2001:4860:4860::8888', '10.255.255.255'):
                with self.subTest(ip=ip), self.assertRaises(ProbePolicyError): policy.approve(ip)
            with patch('app.services.asset_probe_policy.self_addresses', return_value={ipaddress.ip_address('10.1.2.3')}):
                with self.assertRaises(ProbePolicyError): ProbePolicy().approve('10.1.2.3')
            self.assertEqual(len(policy.targets(['10.1.2.0/30', '172.20.0.0/30', '192.168.50.0/30'], [])), 6)
            with self.assertRaises(ProbePolicyError): policy.targets(['10.0.0.0/8'], [])
            with self.assertRaises(ProbePolicyError): policy.targets(['172.0.0.0/8'], [])
            with patch.object(probes, 'bounded_process', return_value=(0, b'["10.1.2.3","172.20.0.1"]')):
                self.assertEqual(probes.resolve('internal.example', policy), ['10.1.2.3', '172.20.0.1'])
            with patch.object(probes, 'bounded_process', return_value=(0, b'["10.1.2.3","8.8.8.8"]')):
                with self.assertRaises(ProbePolicyError): probes.resolve('mixed.example', policy)
            a = self.asset()
            self.request('PUT', f"/api/assets/{a['id']}/monitoring", {'expected_version': 0, 'target': '10.1.2.3', 'enabled': True}, expected=422)
            self.request('POST', '/api/asset-discovery/profiles', {'name': 'Private', 'networks': ['172.20.0.0/30'], 'enabled': True}, expected=422)
            self.monitor(a['id'])
            self.profile()
            with get_connection() as conn:
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM asset_network_jobs').fetchone()[0], 0)
        with patch.object(config, 'ASSET_PROBE_ALLOWED_CIDRS', '192.168.50.0/24'):
            with self.assertRaises(ProbePolicyError): ProbePolicy().approve('10.1.2.3')
        with patch.object(config, 'ASSET_PROBE_ALLOWED_CIDRS', ''):
            with self.assertRaises(ProbePolicyError): ProbePolicy().approve('192.168.50.5')

    def test_roles_privacy_csrf_and_catalog(self):
        a = self.asset(); self.monitor(a['id'])
        for path in ('/api/assets/1/monitoring', '/api/asset-discovery/candidates', '/asset-discovery'):
            self.assertEqual(self.client.get(path).status_code, 401)
        self.request('GET', '/api/asset-discovery/candidates', role='viewer', expected=403)
        self.request('GET', '/api/asset-discovery/profiles', role='analyst', expected=403)
        self.request('PUT', f"/api/assets/{a['id']}/monitoring", {'expected_version': 1, 'target': '192.168.50.5'}, role='analyst', expected=403)
        self.client.cookies.set('access_token', self.headers['admin']['Authorization'][7:])
        response = self.client.post('/api/asset-discovery/profiles', json={'name': 'Lab', 'networks': ['192.168.50.0/30']})
        self.assertEqual(response.status_code, 403)
        csrf = self.client.get('/api/assets/session').json()['csrf_token']
        response = self.client.post('/api/asset-discovery/profiles', json={'name': 'Lab', 'networks': ['192.168.50.0/30']},
                                    headers={'Origin': 'http://testserver', 'X-CSRF-Token': csrf})
        self.assertEqual(response.status_code, 201, response.text)
        catalog = {(r['path'], r['method']): r['auth_required'] for r in get_api_endpoints_catalog()}
        self.assertEqual(catalog[('/api/asset-discovery/profiles', 'POST')], 'Admin')
        self.assertEqual(catalog[('/api/assets/{asset_id}/monitoring/check', 'POST')], 'Analyst / Admin')
        self.assertNotIn('Private lab', self.client.get('/', headers={'X-API-Key': 'invalid'}).text)

    def test_disabled_flags_and_empty_scope_send_nothing(self):
        a = self.asset(); self.monitor(a['id'])
        self.enqueue('monitor', a['id'])
        with patch.object(config, 'FEATURE_ASSET_MONITORING', False):
            self.assertIsNone(worker.claim_job())
        with patch.object(config, 'ASSET_PROBE_ALLOWED_CIDRS', ''):
            self.request('PUT', f"/api/assets/{a['id']}/monitoring", {'expected_version': 1, 'target': '192.168.50.5', 'enabled': True, 'authorized': True}, expected=422)
        code = """from scratch import test_support
import os
os.environ.update(FEATURE_ASSET_PRIORITIZATION='true',FEATURE_ASSET_MONITORING='false',FEATURE_ASSET_DISCOVERY='false')
from app.database import initialize_database
initialize_database()
from app.main import app
from fastapi.testclient import TestClient
c=TestClient(app)
for p in ('/asset-discovery','/api/asset-discovery/candidates','/api/asset-monitoring/status','/api/assets/1/monitoring'):
 r=c.get(p); assert r.status_code==404,(p,r.text); assert 'no-store' in r.headers['cache-control']
assert '/api/asset-discovery/profiles' not in app.openapi()['paths']
"""
        result = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_monitor_threshold_stale_unknown_and_archive_no_inventory_revision(self):
        a = self.asset(); self.monitor(a['id'], failure_threshold=2)
        self.enqueue('monitor', a['id']); job = worker.claim_job()
        with patch.object(probes, 'check', return_value={'outcome': 'down', 'reason': 'target_timeout'}): worker.execute_job(job)
        current = network.monitoring(a['id'])
        self.assertEqual(current['state']['availability'], 'unknown'); self.assertEqual(current['state']['failures'], 1)
        with get_connection() as conn:
            row = conn.execute('SELECT * FROM asset_monitor_configs WHERE asset_id=?', (a['id'],)).fetchone()
            previous = json.loads(row['state_json'])
            state = network.state_after(previous, {'outcome': 'down', 'reason': 'target_timeout'}, json.loads(row['settings_json']), time.time())
            conn.execute('UPDATE asset_monitor_configs SET state_json=? WHERE asset_id=?', (json.dumps(state), a['id']))
        self.assertEqual(network.monitoring(a['id'])['state']['availability'], 'down')
        with get_connection() as conn:
            row = conn.execute('SELECT * FROM asset_monitor_configs WHERE asset_id=?', (a['id'],)).fetchone()
            self.assertEqual(network.display_state(row, now=time.time() + 901)['availability'], 'stale')
            self.assertEqual(conn.execute('SELECT revision FROM asset_inventory_state').fetchone()[0], 1)
        self.assertEqual(assets.get_asset(a['id'])['row_version'], 1)
        assets.archive_asset(a['id'], {'expected_version': 1, 'archived': True}, self.actor)
        assets.archive_asset(a['id'], {'expected_version': 2, 'archived': False}, self.actor)
        self.assertEqual(network.monitoring(a['id'])['state']['availability'], 'disabled')
        self.assertTrue(verify_audit_log_integrity()['is_valid'])

    def test_generation_late_result_and_concurrent_job_claim(self):
        a = self.asset(); current = self.monitor(a['id'])
        job = self.enqueue('monitor', a['id'])
        self.assertEqual(self.enqueue('monitor', a['id'])['id'], job['id'])
        with ThreadPoolExecutor(2) as pool: claims = list(pool.map(lambda _: worker.claim_job(), (1, 2)))
        claimed = next(c for c in claims if c)
        self.assertEqual(sum(c is not None for c in claims), 1)
        network.save_monitor(a['id'], MonitorSettings(**{**current['config']['settings'], 'expected_version': 1, 'target': '192.168.50.6'}), self.actor)
        worker.finish_monitor(claimed, {'outcome': 'up', 'reason': 'late'})
        self.assertEqual(network.monitoring(a['id'])['state']['availability'], 'unknown')
        self.assertEqual(network.get_job(job['id'], 'monitor')['status'], 'cancelled')

    def test_custom_schedule_coalescing_and_global_budget(self):
        p = self.profile(scheduled=True, interval_seconds=1)
        self.assertEqual(p['settings']['interval_seconds'], 1)
        worker.schedule_due(time.time() + 10); worker.schedule_due(time.time() + 20)
        runs = network.list_jobs('discovery', p['id'])
        self.assertEqual(runs['total'], 1); self.assertGreater(runs['items'][0]['skipped_periods'], 0)
        job = worker.claim_job()
        with patch.object(config, 'ASSET_DISCOVERY_RATE_PER_MINUTE', 2):
            self.assertTrue(worker.reserve(job, ['192.168.50.1'], 2))
            self.assertFalse(worker.reserve(job, ['192.168.50.2'], 1))
        for interval in (30, 420, 259200):
            self.assertEqual(DiscoverySettings(name='Intervals', networks=['192.168.50.0/30'], interval_seconds=interval).interval_seconds, interval)

    def test_discovery_candidates_not_assets_and_selective_import(self):
        p = self.profile(); rows = self.discover(p)
        self.assertEqual(len(rows), 4); self.assertEqual(assets.list_assets()['total'], 0)
        self.assertEqual(discovery.candidates(network='192.168.50.0/30')['total'], 2)
        self.assertEqual(set(network.list_jobs('discovery')['items'][0]['result']['networks']), {'192.168.50.0/30', '192.168.51.0/30'})
        selected = rows[0]
        body = DiscoveryImportRequest(items=[{'candidate_id': selected['id'], 'observation_id': selected['observation']['id'],
                'action': 'create', 'asset': {'external_id': 'selected-only', 'name': 'Selected device'}}])
        preview = discovery.preview_import(body, self.actor)
        self.assertEqual(assets.list_assets()['total'], 0)
        result = discovery.commit_import(preview['preview_token'], self.actor)
        self.assertEqual(len(result['items']), 1); self.assertFalse(result['monitoring_enabled'])
        self.assertEqual(assets.list_assets()['total'], 1)
        with get_connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM asset_addresses').fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM asset_monitor_configs').fetchone()[0], 0)
        with self.assertRaises(HTTPException) as exc: discovery.commit_import(preview['preview_token'], self.actor)
        self.assertEqual(exc.exception.status_code, 409)
        self.assertTrue(verify_audit_log_integrity()['is_valid'])

    def test_preview_binding_audit_rollback_link_and_rescan_telemetry(self):
        a = self.asset(); p = self.profile(); rows = self.discover(p)
        selected = rows[0]
        body = DiscoveryImportRequest(items=[{'candidate_id': selected['id'], 'observation_id': selected['observation']['id'],
                'action': 'link', 'asset_id': a['id'], 'expected_version': a['row_version']}])
        preview = discovery.preview_import(body, self.actor)
        with get_connection() as conn: conn.execute('UPDATE asset_discovery_candidates SET last_seen=last_seen+1')
        with self.assertRaises(HTTPException) as exc:
            discovery.commit_import(preview['preview_token'], {**self.actor, 'user_id': -1})
        self.assertEqual(exc.exception.status_code, 404)
        with patch.object(assets, 'log_audit_event', side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError): discovery.commit_import(preview['preview_token'], self.actor)
        with get_connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM asset_addresses').fetchone()[0], 0)
        discovery.commit_import(preview['preview_token'], self.actor)
        current = assets.get_asset(a['id'])
        self.assertEqual(current['name'], a['name']); self.assertEqual(current['exposure'], 'unknown')

    def test_utility_adapters_safe_flags_and_unknown_results(self):
        settings = MonitorSettings(expected_version=0, target='test.example').model_dump(exclude={'expected_version'})
        with patch.object(probes, 'run_utility', return_value=(0, b'CYBERDASH:200')) as utility:
            result = probes.check(settings, '192.168.50.5')
            self.assertEqual(result['outcome'], 'up')
            args = utility.call_args.args[1]
            self.assertIn('--disable', args); self.assertIn('--noproxy', args)
            self.assertIn('test.example:443:192.168.50.5', args); self.assertNotIn('--insecure', args)
        with patch.object(probes, 'run_utility', return_value=(60, b'private certificate text')):
            self.assertEqual(probes.check(settings, '192.168.50.5')['reason'], 'tls_verification_failed')
        with patch.object(probes, 'run_utility', return_value=(2, b'permission denied')):
            result = probes.check({**settings, 'method': 'icmp'}, '192.168.50.5')
            self.assertEqual(result['outcome'], 'unknown'); self.assertNotIn('permission denied', json.dumps(result))
        xml = b'<nmaprun><host><status state="up"/><address addr="192.168.50.5"/></host><runstats><finished exit="success"/></runstats></nmaprun>'
        self.assertEqual(len(probes.parse_nmap(xml, {'192.168.50.5'})), 1)
        for bad in (b'<!DOCTYPE x [<!ENTITY boom "test">]>' + xml, xml.replace(b'192.168.50.5', b'127.0.0.1')):
            with self.assertRaises(probes.ProbeFailure): probes.parse_nmap(bad, {'192.168.50.5'})

    def test_partial_runs_rotate_and_cancel_stops_late_results(self):
        p = self.profile(networks=['192.168.50.0/28'])
        self.enqueue('discovery', p['id']); job = worker.claim_job()
        with patch.object(probes, 'discover', return_value=[]): worker.execute_job(job)
        current = network.get_job(job['id'], 'discovery')
        self.assertEqual(current['processed'], 8); self.assertEqual(current['status'], 'queued')
        with get_connection() as conn:
            conn.execute('UPDATE asset_network_jobs SET started_at=?,available_at=0 WHERE id=?', (time.time() - 1801, job['id']))
        worker.execute_job(worker.claim_job())
        self.assertEqual(network.get_job(job['id'], 'discovery')['status'], 'partial')
        with get_connection() as conn: conn.execute('UPDATE asset_discovery_profiles SET last_request=NULL WHERE id=?', (p['id'],))
        network.request_job('discovery', p['id'], CheckRequest(expected_generation=1, idempotency_key='next-rotation'), self.actor)
        job = worker.claim_job()
        with patch.object(probes, 'discover', return_value=[]) as utility:
            worker.execute_job(job)
            self.assertEqual(utility.call_args.args[0][0], '192.168.50.9')
        with get_connection() as conn: conn.execute('UPDATE asset_network_jobs SET available_at=0 WHERE id=?', (job['id'],))
        job = worker.claim_job(); network.cancel_job(job['id'], self.actor)
        worker.finish_discovery(job, (['192.168.50.1'], [{'address': '192.168.50.1', 'evidence': 'late'}], [[]], 14))
        self.assertEqual(discovery.candidates()['total'], 0)

    def test_shared_address_dns_budgets_and_permission_revocation(self):
        a = self.asset(); self.monitor(a['id']); p = self.profile()
        self.enqueue('monitor', a['id']); self.enqueue('discovery', p['id'])
        monitor = worker.claim_job(); scan = worker.claim_job()
        self.assertTrue(worker.reserve(monitor, ['192.168.50.1'], 1))
        self.assertFalse(worker.reserve(scan, ['192.168.50.1'], 2))
        self.assertEqual(scan['_defer_reason'], 'target_inflight')
        with patch.object(config, 'ASSET_PROBE_DNS_RATE_PER_MINUTE', 1):
            self.assertTrue(worker.reserve_dns(scan, 1)); self.assertFalse(worker.reserve_dns(monitor, 1))
        worker.defer(monitor)
        self.assertEqual(network.get_job(monitor['id'], 'monitor')['result']['reason'], 'dns_budget')
        with get_connection() as conn:
            actor = json.loads(conn.execute('SELECT actor_json FROM asset_network_jobs WHERE id=?', (scan['id'],)).fetchone()[0])
            self.assertNotIn('jti', actor); self.assertNotIn('expires_at', actor)
            conn.execute("UPDATE users SET role='viewer' WHERE id=?", (self.actor['user_id'],))
        try:
            self.assertFalse(worker.still_owned(scan))
        finally:
            with get_connection() as conn: conn.execute("UPDATE users SET role='admin' WHERE id=?", (self.actor['user_id'],))

    def test_multiple_links_same_asset_and_stale_preview_conflicts(self):
        a = self.asset(); rows = self.discover(self.profile())
        body = DiscoveryImportRequest(items=[{'candidate_id': r['id'], 'observation_id': r['observation']['id'],
                'action': 'link', 'asset_id': a['id'], 'expected_version': 1} for r in rows[:2]])
        preview = discovery.preview_import(body, self.actor)
        discovery.commit_import(preview['preview_token'], self.actor)
        self.assertEqual(assets.get_asset(a['id'])['row_version'], 3)
        with get_connection() as conn: self.assertEqual(conn.execute('SELECT COUNT(*) FROM asset_addresses').fetchone()[0], 2)
        r = rows[2]
        body = DiscoveryImportRequest(items=[{'candidate_id': r['id'], 'observation_id': r['observation']['id'], 'action': 'create',
                                             'asset': {'external_id': 'conflict', 'name': 'Conflict'}}])
        preview = discovery.preview_import(body, self.actor)
        with get_connection() as conn: conn.execute('UPDATE asset_discovery_candidates SET identity_version=identity_version+1 WHERE id=?', (r['id'],))
        with self.assertRaises(HTTPException) as exc: discovery.commit_import(preview['preview_token'], self.actor)
        self.assertEqual(exc.exception.status_code, 409)
        self.assertEqual(assets.list_assets()['total'], 1)

    def test_offline_pause_after_restore_keeps_data_and_cancels_work(self):
        a = self.asset(); self.monitor(a['id']); p = self.profile()
        self.enqueue('monitor', a['id']); self.enqueue('discovery', p['id'])
        from scripts.pause_asset_network import pause
        pause()
        self.assertEqual(network.monitoring(a['id'])['state']['availability'], 'disabled')
        self.assertFalse(network.profile(p['id'])['enabled'])
        self.assertTrue(all(r['status'] == 'cancelled' for r in network.list_jobs('discovery')['items']))
        self.assertEqual(assets.list_assets()['total'], 1)
        self.assertTrue(verify_audit_log_integrity()['is_valid'])

    def test_version_one_upgrade_is_additive_and_rolls_back_atomically(self):
        legacy = Path(test_support._sandbox.name) / 'network-upgrade.db'
        from app import database
        from app.network_migrations import apply_network_migration
        with patch.object(database, 'DATABASE_PATH', legacy):
            with patch('app.network_migrations.apply_network_migration'), patch('app.case_migrations.apply_case_migration'): initialize_database()
            asset = assets.create_asset({'external_id': 'legacy', 'name': 'Existing inventory'}, {'username': 'fixture', 'role': 'admin'})
            with self.assertRaises(RuntimeError):
                with get_connection() as conn:
                    conn.execute('BEGIN IMMEDIATE'); apply_network_migration(conn); raise RuntimeError('interrupted migration')
            with get_connection() as conn:
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0], 1)
                self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='asset_network_jobs'").fetchone())
            initialize_database()
            self.assertEqual(assets.get_asset(asset['id'])['name'], 'Existing inventory')
            with get_connection() as conn:
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM asset_network_jobs').fetchone()[0], 0)

    def test_subprocess_timeout_output_limit_and_sanitized_environment(self):
        self.guard.stop()
        original = probes.subprocess.Popen
        processes = []
        def factory(command, **kwargs):
            self.assertNotIn('JWT_SECRET_KEY', kwargs['env'])
            self.assertNotIn('HTTP_PROXY', kwargs['env'])
            self.assertTrue(kwargs['start_new_session']); self.assertTrue(kwargs['close_fds'])
            process = original([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
            processes.append(process); return process
        with patch.object(probes.subprocess, 'Popen', side_effect=factory):
            start = time.monotonic()
            with self.assertRaises(probes.ProbeFailure) as exc: probes.bounded_process('unused', '', timeout=.15)
            self.assertEqual(exc.exception.code, 'execution_timeout')
            self.assertLess(time.monotonic() - start, 2)
        self.assertIsNotNone(processes[0].returncode)
        def noisy(command, **kwargs):
            return original([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"x"*100000)'], **kwargs)
        with patch.object(probes.subprocess, 'Popen', side_effect=noisy):
            with self.assertRaises(probes.ProbeFailure) as exc: probes.bounded_process('unused', '', maximum=1024)
            self.assertEqual(exc.exception.code, 'output_limit')

    def test_disabled_drafts_need_no_network_scope_but_enable_does(self):
        a = self.asset()
        with patch.object(config, 'ASSET_PROBE_ALLOWED_CIDRS', ''):
            data = self.request('PUT', f"/api/assets/{a['id']}/monitoring", {'expected_version': 0, 'target': '192.168.50.5'})
            self.assertFalse(data['config']['enabled'])
            self.request('PUT', f"/api/assets/{a['id']}/monitoring", {'expected_version': 1, 'target': '192.168.50.5', 'enabled': True, 'authorized': True}, expected=422)
            self.request('POST', '/api/asset-discovery/profiles', {'name': 'Disabled draft', 'networks': ['192.168.50.0/30']}, expected=201)

    def test_html_forms_status_filters_and_request_limits(self):
        a = self.asset(); self.monitor(a['id'])
        self.assertIn('Configure availability', self.client.get(f"/assets/{a['id']}", headers=self.headers['admin']).text)
        self.assertNotIn('id="monitor-form"', self.client.get(f"/assets/{a['id']}", headers=self.headers['viewer']).text)
        page = self.client.get('/asset-discovery', headers=self.headers['admin']).text
        self.assertIn('Import selected', page)
        self.assertIn('DNS hostnames are labels returned by the resolver, not verified device identities.', page)
        script = self.client.get('/static/js/asset_network.js')
        self.assertEqual(script.status_code, 200)
        self.assertNotIn('(untrusted DNS)', script.text)
        self.assertIn("${c.hostname || 'no hostname found'}", script.text)
        self.assertEqual(self.request('GET', '/api/assets?availability=unknown')['total'], 1)
        self.assertEqual(self.request('GET', '/api/assets?availability=up')['total'], 0)
        response = self.client.post('/api/asset-discovery/profiles', headers={**self.headers['admin'], 'Content-Type': 'application/json'}, content=iter([b'x' * 40000, b'x' * 40000]))
        self.assertEqual(response.status_code, 413)

    def test_changed_names_require_review_and_imported_evidence_survives_cleanup(self):
        p = self.profile(); candidate = self.discover(p)[0]
        body = DiscoveryImportRequest(items=[{'candidate_id': candidate['id'], 'observation_id': candidate['observation']['id'],
                'action': 'create', 'asset': {'external_id': 'preserved', 'name': 'Do not rename'}}])
        result = discovery.commit_import(discovery.preview_import(body, self.actor)['preview_token'], self.actor)
        asset_id = result['items'][0]['asset_id']
        with get_connection() as conn:
            job = dict(conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (candidate['observation']['job_id'],)).fetchone())
            discovery.record_observation(conn, job, {'address': candidate['address'], 'evidence': 'new_response'},
                                         [{'name': 'changed-name.example.test', 'source': 'PTR', 'forward_confirmed': False}], time.time())
        changed = next(r for r in discovery.candidates()['items'] if r['id'] == candidate['id'])
        self.assertTrue(changed['needs_review']); self.assertIsNone(changed['imported_asset_id'])
        self.assertEqual(assets.get_asset(asset_id)['name'], 'Do not rename')
        body = DiscoveryImportRequest(items=[{'candidate_id': changed['id'], 'observation_id': changed['observation']['id'],
                'action': 'link', 'asset_id': asset_id, 'expected_version': 1}])
        discovery.commit_import(discovery.preview_import(body, self.actor)['preview_token'], self.actor)
        with get_connection() as conn:
            snapshots = [r[0] for r in conn.execute('SELECT snapshot_json FROM asset_discovery_links ORDER BY id')]
            self.assertEqual(len(snapshots), 2)
            conn.execute('DELETE FROM asset_discovery_observations')
            conn.execute('DELETE FROM asset_discovery_candidates')
        response = self.request('GET', f'/api/assets/{asset_id}/discovery-evidence')
        self.assertEqual(response['total'], 2)
        self.assertTrue(all(row['observation_id'] is None and row['candidate_id'] is None for row in response['items']))
        self.assertEqual(set(snapshots), {row['snapshot_json'] for row in response['items']})


from fastapi import HTTPException

if __name__ == '__main__':
    unittest.main(verbosity=2)
