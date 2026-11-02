"""Independent bounded scheduler/worker; durable claims coordinate web workers."""
import json
import ipaddress
import threading
import time
import uuid
from functools import lru_cache
from datetime import datetime, timezone

from fastapi import HTTPException

from app import config
from app.database import get_connection
from app.services import asset_service as assets
from app.services import asset_network_service as network
from app.services import asset_probe_service as probes
from app.services.asset_probe_policy import ProbePolicy, ProbePolicyError
from app.services.asset_discovery_service import record_observation
from app.models.asset_network_schemas import MonitorSettings, DiscoverySettings

_stop = threading.Event()
_threads = []
_guard = threading.Lock()


def feature_enabled(kind):
    return config.FEATURE_ASSET_PRIORITIZATION and (config.FEATURE_ASSET_MONITORING if kind == 'monitor' else config.FEATURE_ASSET_DISCOVERY)


def enabled_job(conn, job, now=None):
    now = time.time() if now is None else now
    if not feature_enabled(job['kind']):
        return False
    try:
        if job['source'] == 'manual':
            actor = json.loads(job['actor_json'])
            if actor.get('is_api_token'):
                token = conn.execute('SELECT role,is_active,expires_at FROM api_tokens WHERE id=?', (actor.get('token_id'),)).fetchone()
                if not token or not token['is_active'] or token['role'] not in ('analyst', 'admin'):
                    return False
                if token['expires_at']:
                    expiry = datetime.fromisoformat(token['expires_at'].replace('Z', '+00:00'))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry.timestamp() <= now:
                        return False
            else:
                user = conn.execute('SELECT role FROM users WHERE id=?', (actor.get('user_id'),)).fetchone()
                if not user or user['role'] not in ('analyst', 'admin'):
                    return False
        row = network.scope_row(conn, job['kind'], job['asset_id'] if job['kind'] == 'monitor' else job['profile_id'])
        return row['generation'] == job['generation'] and ProbePolicy().fingerprint == job['policy_hash']
    except (HTTPException, ProbePolicyError, ValueError, TypeError):
        return False


def schedule_due(now=None):
    now = time.time() if now is None else now
    with assets.write_transaction() as conn:
        for kind, table, column in (('monitor', 'asset_monitor_configs', 'asset_id'), ('discovery', 'asset_discovery_profiles', 'id')):
            if not feature_enabled(kind):
                continue
            rows = conn.execute(f'SELECT * FROM {table} WHERE enabled=1 AND next_due IS NOT NULL AND next_due<=? ORDER BY next_due LIMIT 20', (now,)).fetchall()
            for row in rows:
                settings = json.loads(row['settings_json'])
                if not settings['scheduled']:
                    continue
                interval = settings['interval_seconds']
                missed = int(max(0, now - row['next_due']) // interval)
                try:
                    # Do not backfill missed periods. Existing work is returned/coalesced.
                    object_id = row[column]
                    network.scope_row(conn, kind, object_id)
                    job_column = 'asset_id' if kind == 'monitor' else 'profile_id'
                    active = conn.execute(f"SELECT 1 FROM asset_network_jobs WHERE {job_column}=? AND status IN ('queued','running')", (object_id,)).fetchone()
                    result = network.enqueue(conn, kind, object_id, row, network.SYSTEM_ACTOR, 'scheduled')
                    conn.execute('UPDATE asset_network_jobs SET skipped_periods=skipped_periods+? WHERE id=?', (missed + int(bool(active)), result['id']))
                    conn.execute(f'UPDATE {table} SET next_due=? WHERE {column}=?', (now + interval, object_id))
                except HTTPException as exc:
                    if exc.status_code in (404, 409):
                        conn.execute(f'UPDATE {table} SET next_due=NULL WHERE {column}=?', (row[column],))
                    elif exc.status_code in (422, 503):
                        conn.execute(f'UPDATE {table} SET next_due=? WHERE {column}=?', (now + 60, row[column]))
                    else:
                        raise


def claim_job():
    now, owner = time.time(), uuid.uuid4().hex
    with assets.write_transaction() as conn:
        conn.execute('DELETE FROM asset_network_locks WHERE expires_at<=?', (now,))
        expired = conn.execute("SELECT * FROM asset_network_jobs WHERE status='running' AND lease_until<=?", (now,)).fetchall()
        for job in expired:
            conn.execute("UPDATE asset_network_jobs SET status='error',completed_at=?,result_json=? WHERE id=?",
                         (now, assets.canonical({'reason': 'worker_interrupted', 'outcome': 'unknown'}), job['id']))
            if job['kind'] == 'monitor':
                row = conn.execute('SELECT * FROM asset_monitor_configs WHERE asset_id=?', (job['asset_id'],)).fetchone()
                if row and row['generation'] == job['generation']:
                    state = network.state_after(json.loads(row['state_json']), {'outcome': 'unknown', 'reason': 'worker_interrupted'}, json.loads(row['settings_json']), now)
                    conn.execute('UPDATE asset_monitor_configs SET state_json=? WHERE asset_id=?', (assets.canonical(state), job['asset_id']))
        if conn.execute("SELECT COUNT(*) FROM asset_network_jobs WHERE status='running'").fetchone()[0] >= 2:
            return None
        rows = conn.execute("SELECT * FROM asset_network_jobs WHERE status='queued' AND available_at<=? ORDER BY available_at,id LIMIT 200", (now,)).fetchall()
        for job in rows:
            if not enabled_job(conn, job, now):
                conn.execute("UPDATE asset_network_jobs SET status='cancelled',completed_at=?,result_json=? WHERE id=?", (now, assets.canonical({'reason': 'disabled_or_policy_changed'}), job['id']))
                continue
            if job['kind'] == 'discovery' and conn.execute("SELECT 1 FROM asset_network_jobs WHERE kind='discovery' AND status='running'").fetchone():
                continue
            conn.execute("UPDATE asset_network_jobs SET status='running',owner=?,lease_until=?,started_at=COALESCE(started_at,?) WHERE id=?", (owner, now + 45, now, job['id']))
            return dict(conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone())
    return None


def still_owned(job):
    if _stop.is_set():
        return False
    with get_connection() as conn:
        row = conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone()
        return bool(row and row['status'] == 'running' and row['owner'] == job['owner']
                    and row['lease_until'] > time.time() and enabled_job(conn, row))


def reserve(job, addresses, cost):
    """Shared fixed-window budgets plus address locks; transaction never spans I/O."""
    now = time.time(); window = int(now // 60)
    limit = config.ASSET_PROBE_RATE_PER_MINUTE if job['kind'] == 'monitor' else config.ASSET_DISCOVERY_RATE_PER_MINUTE
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone()
        if not row or row['status'] != 'running' or row['owner'] != job['owner'] or row['lease_until'] <= now or not enabled_job(conn, row):
            return False
        conn.execute('DELETE FROM asset_network_locks WHERE expires_at<=?', (now,))
        if any(conn.execute('SELECT 1 FROM asset_network_locks WHERE address=?', (ip,)).fetchone() for ip in addresses):
            job['_defer_reason'] = 'target_inflight'
            return False
        used = conn.execute('SELECT count FROM asset_network_budget WHERE kind=? AND window=?', (job['kind'], window)).fetchone()
        if (used[0] if used else 0) + cost > limit:
            job['_defer_reason'] = 'traffic_budget'
            job['_defer_until'] = (window + 1) * 60 + .1
            return False
        conn.execute('INSERT INTO asset_network_budget(kind,window,count) VALUES (?,?,?) ON CONFLICT(kind,window) DO UPDATE SET count=count+excluded.count', (job['kind'], window, cost))
        conn.executemany('INSERT INTO asset_network_locks(address,owner,expires_at) VALUES (?,?,?)', [(ip, job['owner'], now + 45) for ip in addresses])
        return True


def defer(job, delay=1):
    available = max(time.time() + delay, job.get('_defer_until', 0))
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT result_json FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone()
        result = json.loads(row[0]) if row else {}
        result.update(reason=job.get('_defer_reason', 'capacity_deferred'), next_eligible_at=available)
        conn.execute("UPDATE asset_network_jobs SET status='queued',owner=NULL,lease_until=NULL,available_at=?,result_json=? WHERE id=? AND status='running' AND owner=?",
                     (available, assets.canonical(result), job['id'], job['owner']))


def reserve_dns(job, cost):
    now = time.time(); window = int(now // 60)
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone()
        if not row or row['status'] != 'running' or row['owner'] != job['owner'] or row['lease_until'] <= now or not enabled_job(conn, row):
            return False
        used = conn.execute("SELECT count FROM asset_network_budget WHERE kind='dns' AND window=?", (window,)).fetchone()
        if (used[0] if used else 0) + cost > config.ASSET_PROBE_DNS_RATE_PER_MINUTE:
            job['_defer_reason'] = 'dns_budget'
            job['_defer_until'] = (window + 1) * 60 + .1
            return False
        conn.execute("INSERT INTO asset_network_budget VALUES ('dns',?,?) ON CONFLICT(kind,window) DO UPDATE SET count=count+excluded.count", (window, cost))
        return True


def finish_monitor(job, result):
    now = time.time()
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone()
        if not row or row['status'] != 'running' or row['owner'] != job['owner'] or row['lease_until'] <= now or not enabled_job(conn, row):
            return
        monitor = conn.execute('SELECT * FROM asset_monitor_configs WHERE asset_id=?', (job['asset_id'],)).fetchone()
        previous = json.loads(monitor['state_json'])
        state = network.state_after(previous, result, json.loads(job['config_json']), now)
        conn.execute('UPDATE asset_monitor_configs SET state_json=? WHERE asset_id=?', (assets.canonical(state), job['asset_id']))
        conn.execute("UPDATE asset_network_jobs SET status='completed',completed_at=?,result_json=?,processed=1 WHERE id=?", (now, assets.canonical(result), job['id']))
        if state.get('stable', 'unknown') != previous.get('stable', 'unknown') or (result['outcome'] == 'unknown' and result.get('reason') != previous.get('latest', {}).get('reason')):
            assets.audit(conn, network.SYSTEM_ACTOR, 'ASSET_AVAILABILITY_CHANGED', job['asset_id'], {'availability': state.get('stable', 'unknown'), 'reason': result['reason']})


@lru_cache(maxsize=16)
def _profile_targets(config_json, policy_hash):
    p = ProbePolicy()
    if p.fingerprint != policy_hash:
        raise ProbePolicyError('Probe policy changed.')
    settings = json.loads(config_json)
    return tuple(p.targets(settings['networks'], settings['exclusions']))


def discovery_chunk(job, p, settings):
    targets = _profile_targets(job['config_json'], p.fingerprint)
    remaining = len(targets) - job['processed']
    if remaining <= 0:
        return [], [], [], len(targets)
    # A chunk fits the global budget even at very conservative operator settings.
    size = min(8, remaining, max(1, config.ASSET_DISCOVERY_RATE_PER_MINUTE // len(settings['ports'])))
    chosen = []
    for i in range(size):
        ip = targets[(job['cursor'] + i) % len(targets)]
        p.approve(ip)
        if chosen and (':' in chosen[0]) != (':' in ip):
            break
        chosen.append(ip)
    if not reserve(job, chosen, len(chosen) * len(settings['ports'])):
        defer(job, 2)
        return None
    records = probes.discover(chosen, settings, cancelled=lambda: not still_owned(job))
    # Output is never trusted to expand the target set, even for injected adapters.
    if any(record['address'] not in chosen for record in records):
        raise probes.ProbeFailure('unexpected_target')
    named = []
    end = time.monotonic() + 20
    for record in records:
        names = []
        record['dns_status'] = 'not_requested'
        if settings['resolve_names'] and time.monotonic() < end:
            if reserve_dns(job, 9 if settings['forward_confirm'] else 1):
                try:
                    names = probes.reverse_name(record['address'], p, settings['forward_confirm'], cancelled=lambda: not still_owned(job) or time.monotonic() >= end)
                except probes.ProbeFailure:
                    pass  # Responding IPs must survive DNS errors/time limits.
                record['dns_status'] = 'queried' if names else 'unavailable'
            else:
                record['dns_status'] = 'budget_deferred'
        elif settings['resolve_names']:
            record['dns_status'] = 'deadline_deferred'
        named.append(names)
    return chosen, records, named, len(targets)


def finish_discovery(job, data):
    chosen, records, named, target_count = data
    now = time.time(); processed = job['processed'] + len(chosen)
    cursor = (job['cursor'] + len(chosen)) % max(1, target_count)
    complete = processed >= target_count
    partial = not complete and now - job['started_at'] >= 1800
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone()
        if not row or row['status'] != 'running' or row['owner'] != job['owner'] or row['lease_until'] <= now or not enabled_job(conn, row):
            return
        for record, names in zip(records, named):
            record_observation(conn, job, record, names, now)
        conn.execute('UPDATE asset_discovery_profiles SET cursor=? WHERE id=? AND generation=?', (cursor, job['profile_id'], job['generation']))
        status = 'completed' if complete else 'partial' if partial else 'queued'
        previous_result = json.loads(row['result_json'])
        summaries = previous_result.get('networks', {})
        for cidr in json.loads(job['config_json'])['networks']:
            net = ipaddress.ip_network(cidr)
            scanned = [ip for ip in chosen if ipaddress.ip_address(ip).version == net.version and ipaddress.ip_address(ip) in net]
            responses = [r for r in records if r['address'] in scanned]
            if scanned:
                prior = summaries.get(cidr, {})
                summaries[cidr] = {'scanned': prior.get('scanned', 0) + len(scanned), 'responses': prior.get('responses', 0) + len(responses),
                                   'first_checked_at': prior.get('first_checked_at', now), 'last_checked_at': now}
        result = {'reason': 'coverage_complete' if complete else 'deadline_partial' if partial else 'coverage_in_progress',
                  'target_count': target_count, 'next_cursor': cursor, 'runner': config.ASSET_PROBE_SCOPE_LABEL,
                  'networks': summaries,
                  'note': 'No response is not proof a host is absent. Hostnames are untrusted DNS observations.'}
        conn.execute('''UPDATE asset_network_jobs SET status=?,completed_at=?,available_at=?,processed=?,responding=responding+?,cursor=?,
            owner=NULL,lease_until=NULL,result_json=? WHERE id=?''',
                     (status, now if complete or partial else None, now + 1, processed, len(records), cursor, assets.canonical(result), job['id']))
        if partial:
            assets.audit(conn, network.SYSTEM_ACTOR, 'ASSET_DISCOVERY_PARTIAL', job['profile_id'], {'job_id': job['id'], 'processed': processed})


def finish_error(job, reason):
    if job['kind'] == 'monitor':
        return finish_monitor(job, {'outcome': 'unknown', 'reason': reason})
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job['id'],)).fetchone()
        if not row or row['status'] != 'running' or row['owner'] != job['owner'] or row['lease_until'] <= time.time() or not enabled_job(conn, row):
            return
        conn.execute("UPDATE asset_network_jobs SET status='error',completed_at=?,result_json=? WHERE id=?",
                     (time.time(), assets.canonical({'reason': reason, 'outcome': 'unknown'}), job['id']))
        previous = conn.execute("SELECT result_json FROM asset_network_jobs WHERE profile_id=? AND id<? AND status IN ('completed','error','partial') ORDER BY id DESC LIMIT 1", (job['profile_id'], job['id'])).fetchone()
        if not previous or json.loads(previous[0]).get('reason') != reason:
            assets.audit(conn, network.SYSTEM_ACTOR, 'ASSET_DISCOVERY_ERROR', job['profile_id'], {'reason': reason})


def execute_job(job):
    try:
        p = ProbePolicy()
        model = MonitorSettings if job['kind'] == 'monitor' else DiscoverySettings
        settings = model.model_validate({**json.loads(job['config_json']), 'expected_version': 0}).model_dump(mode='json', exclude={'expected_version'})
        if p.fingerprint != job['policy_hash'] or not still_owned(job):
            return
        if job['kind'] == 'monitor':
            deadline = time.monotonic() + 10
            cancelled = lambda: not still_owned(job) or time.monotonic() >= deadline
            try:
                ipaddress.ip_address(settings['target'])
            except ValueError:
                # Charge before DNS so depleted budgets cannot produce unlimited lookups.
                if not reserve(job, [], 1):
                    return defer(job, 2)
                if not reserve_dns(job, 1):
                    return defer(job, 2)
                ip = probes.resolve(settings['target'], p, cancelled)[0]
                if not reserve(job, [ip], 0):
                    return defer(job, 2)
            else:
                ip = p.approve(settings['target'])
                if not reserve(job, [ip], 1):
                    return defer(job, 2)
            finish_monitor(job, probes.check(settings, ip, cancelled))
        else:
            if time.time() - job['started_at'] >= 1800:
                targets = _profile_targets(job['config_json'], p.fingerprint)
                return finish_discovery(job, ([], [], [], len(targets)))
            data = discovery_chunk(job, p, settings)
            if data is not None:
                finish_discovery(job, data)
    except ProbePolicyError:
        finish_error(job, 'target_policy_blocked')
    except probes.ProbeFailure as exc:
        finish_error(job, exc.code)
    except HTTPException as exc:
        finish_error(job, 'staging_capacity' if exc.status_code == 409 else 'request_rejected')
    except Exception:
        # Never log raw utility output, network details, or secret-bearing tracebacks.
        finish_error(job, 'runner_error')
    finally:
        with assets.write_transaction() as conn:
            conn.execute('DELETE FROM asset_network_locks WHERE owner=?', (job['owner'],))


def cleanup(now=None):
    now = time.time() if now is None else now
    with assets.write_transaction() as conn:
        conn.execute('DELETE FROM asset_network_budget WHERE window<?', (int(now // 60) - 2,))
        conn.execute('DELETE FROM asset_discovery_import_previews WHERE expires_at<?', (now,))
        conn.execute('''DELETE FROM asset_discovery_observations WHERE id IN (SELECT id FROM asset_discovery_observations
            WHERE observed_at<? OR id NOT IN (SELECT id FROM asset_discovery_observations ORDER BY id DESC LIMIT 50000) LIMIT 500)''', (now - 30 * 86400,))
        conn.execute('''DELETE FROM asset_discovery_candidates WHERE id IN (SELECT c.id FROM asset_discovery_candidates c
            WHERE c.last_seen<? AND NOT EXISTS(SELECT 1 FROM asset_discovery_observations o WHERE o.candidate_id=c.id) LIMIT 100)''', (now - 30 * 86400,))
        # At most 100 results/scope, 10k monitor results and 1k discovery runs overall.
        conn.execute('''DELETE FROM asset_network_jobs WHERE id IN (SELECT id FROM (
            SELECT id,kind,completed_at,ROW_NUMBER() OVER(PARTITION BY kind,COALESCE(asset_id,profile_id) ORDER BY id DESC) AS scope_rank,
            ROW_NUMBER() OVER(PARTITION BY kind ORDER BY id DESC) AS total_rank FROM asset_network_jobs
            WHERE status NOT IN ('queued','running')) WHERE scope_rank>100 OR (kind='monitor' AND (total_rank>10000 OR completed_at<?))
            OR (kind='discovery' AND (total_rank>1000 OR completed_at<?)) LIMIT 500)''', (now - 7 * 86400, now - 30 * 86400))


def _loop():
    last_cleanup, last_heartbeat = 0, 0
    while not _stop.is_set():
        try:
            if time.monotonic() - last_heartbeat >= 10:
                with get_connection() as conn:
                    conn.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES ('asset_network_heartbeat',?)", (str(time.time()),))
                last_heartbeat = time.monotonic()
            schedule_due()
            if time.monotonic() - last_cleanup > 60:
                cleanup(); last_cleanup = time.monotonic()
            job = claim_job()
            if job:
                execute_job(job)
                continue
        except Exception:
            print('Asset network worker iteration failed; no target details logged.')
        _stop.wait(1)


def start():
    if not config.FEATURE_ASSET_PRIORITIZATION or not (config.FEATURE_ASSET_MONITORING or config.FEATURE_ASSET_DISCOVERY):
        return
    with _guard:
        if any(thread.is_alive() for thread in _threads):
            return
        _threads.clear(); _stop.clear()
        for index in range(2):
            thread = threading.Thread(target=_loop, name=f'asset-network-{index}', daemon=True)
            _threads.append(thread); thread.start()


def stop():
    _stop.set()
    for thread in _threads:
        thread.join(timeout=5)
