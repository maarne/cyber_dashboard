"""Feature 2 acceptance tests: isolated SQLite, no real DNS/provider traffic."""
from scratch import test_support
import hashlib
import json
import os
import re
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

os.environ.update(FEATURE_CASE_MANAGEMENT='true', FEATURE_ASSET_PRIORITIZATION='true')
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.database import initialize_database, get_connection
from app.main import app
from app.models.case_schemas import CaseCreate, CaseEvidence, InvestigationRequest
from app.services import case_service as cases, investigation_snapshot_service as snapshots, ioc_service as ioc
from app.services import auth_service as auth
from app.services.api_token_service import generate_api_token, get_api_endpoints_catalog
from app.services.audit_service import verify_audit_log_integrity

EICAR = '44d88612fea8a8f36de82e1278abb02f'


class CaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        password = auth.generate_secure_random_password(18)
        auth.complete_initial_setup('owner', password)
        for name, role in (('analyst', 'analyst'), ('other', 'analyst'), ('viewer', 'viewer')):
            auth.create_user(name, password, role)
        cls.actors = {name: {'username': name, 'role': auth.get_user_by_username(name)['role'],
                            'user_id': auth.get_user_by_username(name)['id']} for name in ('owner', 'analyst', 'other', 'viewer')}
        cls.headers = {name: {'Authorization': 'Bearer ' + auth.create_access_token(name)} for name in cls.actors}

    def setUp(self):
        test_support.assert_test_database()
        self.client = TestClient(app)
        self.guards = [patch.object(ioc, method, side_effect=AssertionError('Real enrichment forbidden')) for method in ('enrich_ip', 'enrich_domain', 'enrich_url')]
        for guard in self.guards: guard.start()
        with get_connection() as conn:
            for table in ('case_evidence', 'case_notes', 'case_references', 'case_events', 'cases', 'investigation_history', 'investigation_snapshots', 'audit_logs'):
                conn.execute(f'DELETE FROM {table}')

    def tearDown(self):
        for guard in self.guards: guard.stop()
        self.client.close()

    def request(self, method, path, body=None, actor='analyst', expected=200):
        response = self.client.request(method, path, headers=self.headers[actor], **({'json': body} if body is not None else {}))
        self.assertEqual(response.status_code, expected, response.text)
        self.assertIn('no-store', response.headers['cache-control'])
        return response.json()

    def capture(self, value=EICAR, actor='analyst', **fields):
        return self.request('POST', '/api/investigations', {'indicator': value, **fields}, actor, 201)['snapshot']

    def create(self, actor='analyst', **fields):
        return self.request('POST', '/api/cases', {'title': 'Test investigation', **fields}, actor, 201)

    def test_local_only_normalization_unknown_eicar_and_snapshot_reload(self):
        for indicator, expected in (('10.1.2.3', '10.1.2.3'), ('EXAMPLE.COM.', 'example.com'), (EICAR.upper(), EICAR)):
            s = self.capture(indicator)
            self.assertEqual(s['indicator'], expected); self.assertTrue(s['integrity_valid'])
            dossier = s['evidence']['dossier']
            self.assertEqual(dossier['sources']['dns']['status'], 'not_queried')
            self.assertEqual(dossier['sources']['geoip']['status'], 'not_queried')
            self.assertEqual(dossier['verdict'], 'CLEAN' if expected == EICAR else 'UNKNOWN')
            self.assertEqual(self.request('GET', f"/api/investigations/{s['id']}")['sha256'], s['sha256'])
        with get_connection() as conn: self.assertEqual(conn.execute('SELECT COUNT(*) FROM investigation_history').fetchone()[0], 3)

    def test_privacy_roles_on_lists_counts_details_history_html_and_exports(self):
        s = self.capture(); c = self.create(snapshot_id=s['id'])
        for path in ('/cases', f"/cases/{c['id']}", '/api/cases', '/api/cases/assignees', f"/api/cases/{c['id']}",
                     f"/api/cases/{c['id']}/evidence", f"/api/cases/{c['id']}/export", f"/api/investigations/{s['id']}", '/api/investigate/history', '/investigate'):
            self.assertEqual(self.client.get(path).status_code, 401, path)
            self.request('GET', path, actor='viewer', expected=403)
        self.request('POST', '/api/cases', {'title': 'No'}, actor='viewer', expected=403)

    def test_snapshot_binding_and_shared_case_access(self):
        s = self.capture(); self.request('GET', f"/api/investigations/{s['id']}", actor='other', expected=404)
        self.request('POST', '/api/cases', {'title': 'Stolen', 'snapshot_id': s['id']}, actor='other', expected=404)
        c = self.create(snapshot_id=s['id'])
        self.request('GET', f"/api/investigations/{s['id']}", actor='other')
        self.request('GET', f"/api/cases/{c['id']}", actor='other')
        with get_connection() as conn: self.assertEqual(conn.execute('SELECT COUNT(*) FROM cases').fetchone()[0], 1)

    def test_case_edit_note_correction_close_and_reopen_history(self):
        c = self.create(initial_note='Original note')
        c = self.request('PATCH', f"/api/cases/{c['id']}", {'expected_version': 1, 'title': 'Updated', 'severity': 'high'})
        self.request('PATCH', f"/api/cases/{c['id']}", {'expected_version': 1, 'title': 'Stale'}, expected=409)
        note = self.request('GET', f"/api/cases/{c['id']}/notes")['items'][0]
        result = self.request('POST', f"/api/cases/{c['id']}/notes", {'expected_version': 2, 'body': 'Correction', 'supersedes_note_id': note['id']})
        c = result['case']
        self.request('POST', f"/api/cases/{c['id']}/transition", {'expected_version': c['row_version'], 'status': 'closed', 'reason': 'Missing conclusion'}, expected=422)
        self.request('POST', f"/api/cases/{c['id']}/transition", {'expected_version': c['row_version'], 'status': 'closed', 'reason': 'Not owner', 'conclusion': 'benign'}, actor='other', expected=403)
        c = self.request('POST', f"/api/cases/{c['id']}/transition", {'expected_version': c['row_version'], 'status': 'closed', 'reason': 'Authorized EICAR exercise', 'conclusion': 'security_test'})
        self.request('POST', f"/api/cases/{c['id']}/notes", {'expected_version': c['row_version'], 'body': 'Closed edit'}, expected=409)
        c = self.request('POST', f"/api/cases/{c['id']}/transition", {'expected_version': c['row_version'], 'status': 'open', 'reason': 'New evidence'})
        self.assertIsNone(c['conclusion'])
        events = self.request('GET', f"/api/cases/{c['id']}/events")['items']
        self.assertTrue(any(e['payload'].get('conclusion') == 'security_test' for e in events))
        self.assertEqual(len(self.request('GET', f"/api/cases/{c['id']}/notes")['items']), 2)
        self.assertTrue(verify_audit_log_integrity()['is_valid'])

    def test_snapshot_integrity_tamper_warns_on_read_export_rejects_new_attach(self):
        s = self.capture(); c = self.create(snapshot_id=s['id'])
        with get_connection() as conn: conn.execute('UPDATE investigation_snapshots SET payload_json=? WHERE id=?', ('{"dossier":{"verdict":"ALTERED"}}', s['id']))
        result = self.request('GET', f"/api/investigations/{s['id']}")
        self.assertFalse(result['integrity_valid']); self.assertIn('INTEGRITY WARNING', result['warning'])
        report = self.request('GET', f"/api/cases/{c['id']}/export")
        self.assertFalse(report['evidence'][0]['snapshot']['integrity_valid'])
        self.request('POST', '/api/cases', {'title': 'Reject tamper', 'snapshot_id': s['id']}, expected=409)
        self.request('PATCH', f"/api/investigations/{s['id']}", {'payload_json': '{}'}, expected=405)
        self.request('DELETE', f"/api/investigations/{s['id']}", expected=405)

    def test_cookie_csrf_and_origin_required(self):
        self.client.cookies.set('access_token', self.headers['analyst']['Authorization'][7:])
        body = {'title': 'Cookie case'}
        self.assertEqual(self.client.post('/api/cases', json=body).status_code, 403)
        page = self.client.get('/cases').text
        csrf = re.search(r'name="case-csrf-token" content="([a-f0-9]+)"', page)[1]
        r = self.client.post('/api/cases', json=body, headers={'X-CSRF-Token': csrf, 'Origin': 'http://evil.example'})
        self.assertEqual(r.status_code, 403)
        r = self.client.post('/api/cases', json=body, headers={'X-CSRF-Token': csrf, 'Origin': 'http://testserver'})
        self.assertEqual(r.status_code, 201, r.text)

    def test_api_token_identity_assignee_validation_and_export_secret_exclusion(self):
        token, metadata = generate_api_token('case-machine', 'analyst', 'owner', rate_limit=100)
        headers = {'X-API-Key': token}
        response = self.client.post('/api/investigations', json={'indicator': EICAR}, headers=headers)
        self.assertEqual(response.status_code, 201, response.text)
        s = response.json()['snapshot']; self.assertEqual(s['actor_token_id'], metadata['id']); self.assertIsNone(s['actor_user_id'])
        response = self.client.post('/api/cases', json={'title': 'Service created', 'snapshot_id': s['id']}, headers=headers)
        self.assertEqual(response.status_code, 201, response.text)
        c = response.json(); self.assertIsNone(c['assignee_user_id']); self.assertEqual(c['actor_token_id'], metadata['id'])
        report = self.client.get(f"/api/cases/{c['id']}/export", headers=headers)
        self.assertNotIn(token, report.text); self.assertNotIn('token_hash', report.text); self.assertNotIn('jti', report.text)
        self.request('POST', '/api/cases', {'title': 'Invalid owner', 'assignee_user_id': self.actors['viewer']['user_id']}, expected=422)

    def test_atomic_audit_failure_and_concurrent_duplicate_attachment(self):
        s = self.capture(); c = self.create()
        with patch('app.services.case_common.log_audit_event', side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError): cases.attach(c['id'], CaseEvidence(expected_version=1, snapshot_id=s['id']), self.actors['analyst'])
        self.assertEqual(cases.collection(c['id'], 'evidence')['items'], [])
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: cases.attach(c['id'], CaseEvidence(expected_version=1, snapshot_id=s['id']), self.actors['analyst']), (1, 2)))
        self.assertEqual(sum(r['attached'] for r in results), 1)
        self.assertEqual(cases.get_case(c['id'])['row_version'], 2)

    def test_capture_failure_rolls_back_snapshot_history_and_audit(self):
        with patch('app.services.case_common.log_audit_event', side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError): snapshots.capture(InvestigationRequest(indicator=EICAR), self.actors['analyst'])
        with get_connection() as conn:
            for table in ('investigation_history', 'investigation_snapshots', 'audit_logs'):
                self.assertEqual(conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0], 0)

    def test_delete_assignee_keeps_evidence_actor_names_and_notes(self):
        name = 'temporary_case_owner'
        auth.create_user(name, auth.generate_secure_random_password(18), 'analyst')
        user_id = auth.get_user_by_username(name)['id']
        actor = {'username': name, 'role': 'analyst', 'user_id': user_id}
        s = snapshots.capture(InvestigationRequest(indicator=EICAR), actor)['snapshot']
        c = cases.create(CaseCreate(title='Preserve account history', snapshot_id=s['id'], initial_note='Original author'), actor)
        self.assertTrue(auth.delete_user_by_username(name))
        c = cases.get_case(c['id']); self.assertIsNone(c['assignee_user_id']); self.assertEqual(c['actor_name'], name)
        self.assertEqual(cases.collection(c['id'], 'notes')['items'][0]['actor_name'], name)
        self.assertTrue(cases.collection(c['id'], 'evidence')['items'][0]['snapshot']['integrity_valid'])

    def test_local_feed_changes_do_not_rewrite_captured_result_and_matching_cases(self):
        s = self.capture('198.51.100.10'); c = self.create(snapshot_id=s['id'])
        result = self.request('POST', '/api/investigations', {'indicator': '198.51.100.10'}, expected=201)
        self.assertEqual(result['matching_cases'][0]['id'], c['id'])
        self.assertNotEqual(result['snapshot']['id'], s['id'])
        self.assertEqual(self.request('GET', f"/api/investigations/{s['id']}")['sha256'], s['sha256'])

    def test_references_search_pagination_archive_and_no_cross_case_corrections(self):
        c = self.create(title='Search %_ literal', initial_note='First')
        other = self.create()
        self.assertEqual(len(self.request('GET', '/api/cases?search=%25_')['items']), 1)
        self.assertEqual(len(self.request('GET', '/api/cases?limit=1')['items']), 1)
        self.assertIsNotNone(self.request('GET', '/api/cases?limit=1')['next_before_id'])
        with get_connection() as conn: rule_id = str(conn.execute('SELECT id FROM detection_rules LIMIT 1').fetchone()[0])
        result = self.request('POST', f"/api/cases/{c['id']}/references", {'expected_version': 1, 'kind': 'rule', 'target_id': rule_id})
        self.assertEqual(self.request('GET', f'/api/cases?reference_kind=rule&target_id={rule_id}')['items'][0]['id'], c['id'])
        first_note = cases.collection(c['id'], 'notes')['items'][0]
        self.request('POST', f"/api/cases/{other['id']}/notes", {'expected_version': 1, 'body': 'Invalid correction', 'supersedes_note_id': first_note['id']}, expected=422)
        self.request('POST', f"/api/cases/{c['id']}/archive", {'expected_version': 2, 'archived': True, 'reason': 'Retain'}, expected=403)
        c = self.request('POST', f"/api/cases/{c['id']}/archive", {'expected_version': 2, 'archived': True, 'reason': 'Retain'}, actor='owner')
        self.assertTrue(c['is_archived']); self.assertEqual(len(self.request('GET', '/api/cases?archived=true')['items']), 1)

    def test_size_limits_snapshot_storage_note_and_report_are_not_truncated(self):
        c = self.create()
        self.request('POST', f"/api/cases/{c['id']}/notes", {'expected_version': 1, 'body': 'x'*8001}, expected=422)
        with patch.object(snapshots, 'MAX_SNAPSHOT_BYTES', 10): self.capture_too_large()
        with patch.object(snapshots, 'MAX_STORAGE_BYTES', 10): self.request('POST', '/api/investigations', {'indicator': EICAR}, expected=409)
        with patch.dict(cases.LIMITS, cases=1): self.request('POST', '/api/cases', {'title': 'Limit'}, expected=409)
        with patch.dict(cases.LIMITS, export_bytes=10): self.request('GET', f"/api/cases/{c['id']}/export", expected=413)
        response = self.client.post('/api/cases', headers={**self.headers['analyst'], 'Content-Type': 'application/json'}, content=iter([b'x'*40000,b'x'*40000]))
        self.assertEqual(response.status_code, 413)

    def capture_too_large(self):
        self.request('POST', '/api/investigations', {'indicator': EICAR}, expected=413)

    def test_url_credentials_invalid_inputs_and_export_inert_text(self):
        for value in ('https://user:password@example.com/path', 'https://example.com/?api_key=secret', 'https://example.com/#token', 'not an IOC', '-oNcommand'):
            self.request('POST', '/api/investigations', {'indicator': value}, expected=422)
        c = self.create(title='<img src=x onerror=alert(1)>', initial_note='\n```\n<script>alert(1)</script>\n[click](javascript:alert(1))')
        page = self.client.get(f"/cases/{c['id']}", headers=self.headers['analyst'])
        self.assertNotIn('<img src=x', page.text)
        md = self.client.get(f"/api/cases/{c['id']}/export?format=markdown", headers=self.headers['analyst'])
        self.assertEqual(md.status_code, 200); self.assertIn('INTERNAL', md.text)
        self.assertNotIn('<script>', md.text); self.assertIn('attachment;', md.headers['content-disposition'])
        self.assertIn('schema_version', md.text)

    def test_compatibility_get_no_capture_history_clear_retains_evidence(self):
        s = self.capture(); c = self.create(snapshot_id=s['id'])
        r = self.client.get(f'/api/investigate?ioc={EICAR}', headers=self.headers['analyst'])
        self.assertEqual(r.status_code, 200); self.assertEqual(r.json()['verdict'], 'CLEAN'); self.assertEqual(r.headers['deprecation'], 'true')
        self.client.get(f'/investigate?ioc={EICAR}', headers=self.headers['analyst'])
        self.client.get(f"/investigate?snapshot_id={s['id']}", headers=self.headers['analyst'])
        with get_connection() as conn: self.assertEqual(conn.execute('SELECT COUNT(*) FROM investigation_history').fetchone()[0], 1)
        self.request('DELETE', '/api/investigate/history', actor='owner')
        self.assertEqual(len(cases.collection(c['id'], 'evidence')['items']), 1)
        self.assertTrue(self.request('GET', f"/api/investigations/{s['id']}")['integrity_valid'])

    def test_source_timeout_is_preserved_and_pivots_never_mean_provider_queried(self):
        with patch.object(ioc, 'enrich_ip', return_value={'country': 'Unknown', 'geoip_status': 'timeout', 'dns_status': 'unavailable'}):
            s = self.capture('8.8.8.8', local_only=False)
        self.assertEqual(s['evidence']['dossier']['sources']['geoip']['status'], 'timeout')
        self.assertEqual(s['evidence']['dossier']['sources']['external_reputation']['status'], 'not_queried')

    def test_feature_off_and_version_two_upgrade_rolls_back_atomically(self):
        code = """from scratch import test_support
import os
os.environ['FEATURE_CASE_MANAGEMENT']='false'
from app.database import initialize_database
initialize_database()
from app.main import app
from fastapi.testclient import TestClient
c=TestClient(app)
for p in ('/cases','/api/cases','/api/investigations/1'):
 r=c.get(p); assert r.status_code==404,(p,r.text); assert 'no-store' in r.headers['cache-control']
assert '/api/cases' not in app.openapi()['paths']
"""
        r = subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        from app import database
        from app.case_migrations import apply_case_migration
        legacy = Path(test_support._sandbox.name)/'case-upgrade.db'
        with patch.object(database,'DATABASE_PATH',legacy):
            with patch('app.case_migrations.apply_case_migration'), patch('app.rule_migrations.apply_rule_migration'): initialize_database()
            with get_connection() as conn: conn.execute("INSERT INTO investigation_history(indicator,indicator_type,verdict,threat_score) VALUES ('legacy.example','domain','UNKNOWN',0)")
            with self.assertRaises(RuntimeError):
                with get_connection() as conn:
                    conn.execute('BEGIN IMMEDIATE'); apply_case_migration(conn); raise RuntimeError('rollback')
            with get_connection() as conn: self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='cases'").fetchone())
            initialize_database(); initialize_database()
            with get_connection() as conn:
                old = conn.execute('SELECT * FROM investigation_history').fetchone()
                self.assertIsNone(old['actor_name']); self.assertIsNone(old['snapshot_id']); self.assertEqual(old['indicator'],'legacy.example')
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0],4)
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM cases').fetchone()[0],0)
                self.assertFalse(conn.execute('PRAGMA foreign_key_check').fetchall())

    def test_openapi_catalog_permissions(self):
        catalog = {(r['path'],r['method']):r['auth_required'] for r in get_api_endpoints_catalog()}
        self.assertEqual(catalog[('/api/cases','POST')],'Analyst / Admin')
        self.assertEqual(catalog[('/api/cases/{case_id}/archive','POST')],'Admin')
        self.assertEqual(catalog[('/api/investigations','POST')],'Analyst / Admin')
        self.assertEqual(app.openapi()['paths']['/api/investigations']['post']['responses']['201']['content']['application/json']['schema']['$ref'],'#/components/schemas/InvestigationResponse')

    def test_child_limits_and_snapshot_metadata_tamper(self):
        s = self.capture(); c = self.create(initial_note='Initial')
        with patch.dict(cases.LIMITS, evidence_per_case=0):
            self.request('POST', f"/api/cases/{c['id']}/evidence", {'expected_version': 1, 'snapshot_id': s['id']}, expected=409)
        with patch.dict(cases.LIMITS, notes_per_case=1):
            self.request('POST', f"/api/cases/{c['id']}/notes", {'expected_version': 1, 'body': 'Over quota'}, expected=409)
        with get_connection() as conn: conn.execute('UPDATE investigation_snapshots SET indicator=? WHERE id=?', ('tampered.example', s['id']))
        self.assertFalse(self.request('GET', f"/api/investigations/{s['id']}")['integrity_valid'])

    def test_keyset_paging_dates_and_concurrent_case_edit(self):
        first, second = self.create(title='First'), self.create(title='Second')
        page = self.request('GET', '/api/cases?limit=1')
        older = self.request('GET', f"/api/cases?limit=1&before_id={page['next_before_id']}")
        self.assertEqual([page['items'][0]['id'], older['items'][0]['id']], [second['id'], first['id']])
        self.assertEqual(len(self.request('GET', '/api/cases?created_from=2000-01-01&created_to=2099-12-31')['items']), 2)
        def edit(number):
            from app.models.case_schemas import CasePatch
            try:
                cases.patch_case(first['id'], CasePatch(expected_version=1, title=f'Concurrent {number}'), self.actors['analyst'])
                return 200
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(2) as pool: self.assertEqual(sorted(pool.map(edit, (1, 2))), [200, 409])

    def test_case_feature_does_not_require_asset_inventory(self):
        from app import config
        with patch.object(config, 'FEATURE_ASSET_PRIORITIZATION', False):
            c = self.create()
            self.request('POST', f"/api/cases/{c['id']}/references", {'expected_version': 1, 'kind': 'asset', 'target_id': '1'}, expected=404)
            self.capture()


if __name__ == '__main__': unittest.main(verbosity=2)
