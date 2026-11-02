"""Configuration, private reads and durable network jobs. No network I/O here."""
import hashlib
import json
import time

from fastapi import HTTPException

from app import config
from app.database import get_connection
from app.services import asset_service as assets
from app.services.asset_probe_policy import ProbePolicy, ProbePolicyError
from app.services.asset_probe_service import capabilities

SYSTEM_ACTOR = {'username': 'asset-network-worker', 'role': 'system'}


def policy():
    try:
        return ProbePolicy()
    except ProbePolicyError as exc:
        raise HTTPException(422, str(exc)) from exc


def settings_data(model):
    return model.model_dump(mode='json', exclude={'expected_version'})


def config_record(row):
    settings = json.loads(row['settings_json'])
    settings['enabled'] = bool(row['enabled'])
    return {**{k: row[k] for k in row.keys() if k not in ('settings_json', 'state_json')},
            'settings': settings,
            **({'state': json.loads(row['state_json'])} if 'state_json' in row.keys() else {})}


def public_job(row):
    if row is None:
        raise HTTPException(404, 'Network job not found.')
    return {**{key: row[key] for key in ('id', 'kind', 'asset_id', 'profile_id', 'generation', 'source', 'status',
            'due_at', 'available_at', 'started_at', 'completed_at', 'processed', 'responding', 'skipped_periods', 'created_at')},
            'result': json.loads(row['result_json'])}


def display_state(row, archived=False, now=None):
    now = time.time() if now is None else now
    if not row or not row['enabled'] or archived:
        return {'availability': 'disabled', 'latest': None, 'note': 'Not enabled; no traffic requested.'}
    settings, state = json.loads(row['settings_json']), json.loads(row['state_json'])
    availability = state.get('stable', 'unknown')
    if state.get('latest', {}).get('outcome') == 'unknown':
        availability = 'unknown'
    lifetime = 2 * settings['interval_seconds'] + 10 if settings['scheduled'] else 900
    if availability == 'up' and state.get('latest', {}).get('outcome') == 'down' and now > state.get('last_success', 0) + lifetime:
        availability = 'unknown'
    if state.get('measured_at') and now > state['measured_at'] + lifetime:
        availability = 'stale'
    return {**state, 'availability': availability, 'failure_threshold': settings['failure_threshold'],
            'fresh_until': state.get('measured_at', 0) + lifetime if state.get('measured_at') else None,
            'runner': config.ASSET_PROBE_SCOPE_LABEL}


def capabilities_info(admin=False):
    try:
        p = ProbePolicy()
        scope = {'configured': bool(p.networks), 'runner': p.scope}
        if admin:
            scope['allowed_cidrs'] = list(map(str, p.networks))
    except ProbePolicyError as exc:
        scope = {'configured': False, 'error': str(exc)}
    with get_connection() as conn:
        heartbeat = conn.execute("SELECT value FROM app_settings WHERE key='asset_network_heartbeat'").fetchone()
        try:
            heartbeat_at = float(heartbeat[0]) if heartbeat else None
        except (ValueError, TypeError):
            heartbeat_at = None
        counts = dict(conn.execute("SELECT status,COUNT(*) FROM asset_network_jobs WHERE status IN ('queued','running') GROUP BY status").fetchall())
    return {'tools': capabilities(), 'scope': scope, 'runner': {'heartbeat_at': heartbeat_at,
            'recent': bool(heartbeat_at and 0 <= time.time() - heartbeat_at < 30), 'queued': counts.get('queued', 0), 'running': counts.get('running', 0),
            'captured_at': time.time()}, 'limits': {'monitors': 100, 'profiles': 10,
            'targets_per_run': 4096, 'simultaneous_jobs': 2, 'monitor_attempts_per_minute': config.ASSET_PROBE_RATE_PER_MINUTE,
            'discovery_attempts_per_minute': config.ASSET_DISCOVERY_RATE_PER_MINUTE, 'dns_budget_per_minute': config.ASSET_PROBE_DNS_RATE_PER_MINUTE},
            'notice': 'Checks run from this runner only. F1 sleep, permissions, routing and budgets affect effective cadence.'}


def availability_map(conn):
    return {row['asset_id']: display_state(row, row['is_archived']) for row in conn.execute(
        'SELECT c.*,a.is_archived FROM asset_monitor_configs c JOIN assets a ON a.id=c.asset_id WHERE c.enabled=1')}


def monitoring(asset_id):
    with get_connection() as conn:
        asset = assets.get_asset_record(conn, asset_id)
        row = conn.execute('SELECT * FROM asset_monitor_configs WHERE asset_id=?', (asset_id,)).fetchone()
        latest = conn.execute("SELECT * FROM asset_network_jobs WHERE asset_id=? AND status IN ('queued','running') ORDER BY id DESC LIMIT 1", (asset_id,)).fetchone()
        return {'config': config_record(row) if row else None, 'state': display_state(row, asset['is_archived']),
                'job': public_job(latest) if latest else None,
                'addresses': [dict(r) for r in conn.execute('SELECT * FROM asset_addresses WHERE asset_id=? ORDER BY id LIMIT 100', (asset_id,))]}


def cancel_scope(conn, kind, object_id, reason):
    column = 'asset_id' if kind == 'monitor' else 'profile_id'
    conn.execute(f"UPDATE asset_network_jobs SET status='cancelled',completed_at=?,result_json=? WHERE {column}=? AND status IN ('queued','running')",
                 (time.time(), assets.canonical({'reason': reason}), object_id))


def save_monitor(asset_id, model, actor):
    data = settings_data(model)
    try:
        data['target'] = policy().target(data['target'], authorize=data['enabled'])
    except ProbePolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    with assets.write_transaction() as conn:
        assets.get_asset_record(conn, asset_id, writable=True)
        row = conn.execute('SELECT * FROM asset_monitor_configs WHERE asset_id=?', (asset_id,)).fetchone()
        if (row['row_version'] if row else 0) != model.expected_version:
            raise HTTPException(409, 'Monitor configuration changed. Reload first.')
        count = conn.execute('SELECT COUNT(*) FROM asset_monitor_configs WHERE enabled=1 AND asset_id!=?', (asset_id,)).fetchone()[0]
        if data['enabled'] and count >= 100:
            raise HTTPException(409, 'At most 100 enabled monitors.')
        now = time.time()
        cancel_scope(conn, 'monitor', asset_id, 'configuration_changed')
        # Enable/save never sends traffic. Scheduled first run waits one interval.
        due = now + data['interval_seconds'] if data['enabled'] and data['scheduled'] else None
        conn.execute("""INSERT INTO asset_monitor_configs(asset_id,settings_json,enabled,next_due,updated_by,updated_at)
            VALUES (?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET settings_json=excluded.settings_json,
            enabled=excluded.enabled,next_due=excluded.next_due,state_json='{}',generation=generation+1,
            row_version=row_version+1,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                     (asset_id, assets.canonical(data), int(data['enabled']), due, actor['username'], now))
        assets.audit(conn, actor, 'ASSET_MONITOR_CONFIGURED', asset_id, {'enabled': data['enabled'], 'method': data['method']})
    return monitoring(asset_id)


def validate_profile(data):
    p = policy()
    try:
        targets = p.targets(data['networks'], data['exclusions'], authorize=data['enabled'])
    except ProbePolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    import ipaddress
    data['networks'] = list(dict.fromkeys(str(ipaddress.ip_network(n)) for n in data['networks']))
    data['exclusions'] = list(dict.fromkeys(str(ipaddress.ip_network(n)) for n in data['exclusions']))
    estimate = len(targets) * len(data['ports']) / config.ASSET_DISCOVERY_RATE_PER_MINUTE * 60
    if data['enabled'] and len(data['ports']) > config.ASSET_DISCOVERY_RATE_PER_MINUTE:
        raise HTTPException(422, 'One target needs more port attempts than the operator minute budget. Use fewer discovery ports or increase the operator budget.')
    if estimate > 1800 and not data['allow_partial']:
        raise HTTPException(422, 'Estimated pass exceeds the 30-minute run budget. Split the scope, adjust operator pacing, or explicitly accept rotating partial coverage.')
    return {'target_count': len(targets), 'minimum_estimated_seconds': round(estimate, 2),
            'warning': 'Requested interval is shorter than estimated coverage time; runs will coalesce/defer.' if data['interval_seconds'] < estimate else None}


def save_profile(profile_id, model, actor):
    data = settings_data(model)
    estimate = validate_profile(data)
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT * FROM asset_discovery_profiles WHERE id=?', (profile_id,)).fetchone() if profile_id else None
        if profile_id and not row:
            raise HTTPException(404, 'Discovery profile not found.')
        if (row['row_version'] if row else 0) != model.expected_version:
            raise HTTPException(409, 'Profile changed. Reload first.')
        if not row and conn.execute('SELECT COUNT(*) FROM asset_discovery_profiles').fetchone()[0] >= 50:
            raise HTTPException(409, 'At most 50 retained discovery profiles.')
        count = conn.execute('SELECT COUNT(*) FROM asset_discovery_profiles WHERE enabled=1 AND id!=?', (profile_id or 0,)).fetchone()[0]
        if data['enabled'] and count >= 10:
            raise HTTPException(409, 'At most ten enabled discovery profiles.')
        now = time.time()
        due = (max(now + 1, data['first_run_at']) if data.get('first_run_at') else now + data['interval_seconds']) if data['enabled'] and data['scheduled'] else None
        if row:
            cancel_scope(conn, 'discovery', profile_id, 'profile_changed')
            conn.execute('UPDATE asset_discovery_profiles SET settings_json=?,enabled=?,next_due=?,generation=generation+1,row_version=row_version+1,cursor=0,updated_by=?,updated_at=? WHERE id=?',
                         (assets.canonical(data), int(data['enabled']), due, actor['username'], now, profile_id))
        else:
            profile_id = conn.execute('INSERT INTO asset_discovery_profiles(settings_json,enabled,next_due,updated_by,updated_at) VALUES (?,?,?,?,?)',
                                      (assets.canonical(data), int(data['enabled']), due, actor['username'], now)).lastrowid
        assets.audit(conn, actor, 'ASSET_DISCOVERY_PROFILE_CONFIGURED', profile_id, {'enabled': data['enabled'], 'networks': len(data['networks'])})
        result = config_record(conn.execute('SELECT * FROM asset_discovery_profiles WHERE id=?', (profile_id,)).fetchone())
    return {**result, 'estimate': estimate}


def profiles():
    with get_connection() as conn:
        return {'items': [config_record(row) for row in conn.execute('SELECT * FROM asset_discovery_profiles ORDER BY id DESC LIMIT 50')]}


def profile(profile_id):
    with get_connection() as conn:
        row = conn.execute('SELECT * FROM asset_discovery_profiles WHERE id=?', (profile_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'Discovery profile not found.')
        return config_record(row)


def scope_row(conn, kind, object_id):
    if kind == 'monitor':
        asset = assets.get_asset_record(conn, object_id)
        row = conn.execute('SELECT * FROM asset_monitor_configs WHERE asset_id=?', (object_id,)).fetchone()
        if asset['is_archived']:
            raise HTTPException(409, 'Archived assets cannot be probed.')
    else:
        row = conn.execute('SELECT * FROM asset_discovery_profiles WHERE id=?', (object_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'Network configuration not found.')
    if not row['enabled']:
        raise HTTPException(409, 'Enable the approved configuration first.')
    return row


def enqueue(conn, kind, object_id, row, actor, source, key=None):
    now = time.time()
    column = 'asset_id' if kind == 'monitor' else 'profile_id'
    principal_key = assets.actor_key(actor) if source == 'manual' else 'system'
    actor_snapshot = {name: actor[name] for name in ('username', 'role', 'user_id', 'token_id', 'is_api_token') if name in actor}
    actor_snapshot['principal_key'] = principal_key
    if key:
        previous = conn.execute(f"SELECT * FROM asset_network_jobs WHERE {column}=? AND idempotency_key=? AND json_extract(actor_json,'$.principal_key')=? ORDER BY id DESC LIMIT 1",
                                (object_id, key, principal_key)).fetchone()
        if previous:
            return public_job(previous)
    active = conn.execute(f"SELECT * FROM asset_network_jobs WHERE {column}=? AND status IN ('queued','running')", (object_id,)).fetchone()
    if active:
        return public_job(active)
    if source == 'manual' and row['last_request'] and now - row['last_request'] < 60:
        raise HTTPException(429, 'One manual request per target/profile per minute.', headers={'Retry-After': '60'})
    if conn.execute("SELECT COUNT(*) FROM asset_network_jobs WHERE status IN ('queued','running')").fetchone()[0] >= 200:
        raise HTTPException(503, 'Network job queue full.', headers={'Retry-After': '60'})
    retained_limit = 10000 if kind == 'monitor' else 1000
    if conn.execute("SELECT COUNT(*) FROM asset_network_jobs WHERE kind=? AND status NOT IN ('queued','running')", (kind,)).fetchone()[0] >= retained_limit:
        conn.execute("DELETE FROM asset_network_jobs WHERE id IN (SELECT id FROM asset_network_jobs WHERE kind=? AND status NOT IN ('queued','running') ORDER BY id LIMIT 100)", (kind,))
    p = policy()
    if not p.networks:
        raise HTTPException(422, 'No operator-approved network scope is configured.')
    job_id = conn.execute(f"""INSERT INTO asset_network_jobs(kind,{column},generation,config_json,policy_hash,actor_json,source,status,
        idempotency_key,due_at,available_at,cursor,created_at) VALUES (?,?,?,?,?,?,?,'queued',?,?,?,?,?)""",
                          (kind, object_id, row['generation'], row['settings_json'], p.fingerprint, assets.canonical(actor_snapshot), source,
                           key, (row['next_due'] or now) if source == 'scheduled' else now, now, row['cursor'] if kind == 'discovery' else 0, now)).lastrowid
    table = 'asset_monitor_configs' if kind == 'monitor' else 'asset_discovery_profiles'
    id_column = 'asset_id' if kind == 'monitor' else 'id'
    if source == 'manual':
        conn.execute(f'UPDATE {table} SET last_request=? WHERE {id_column}=?', (now, object_id))
        assets.audit(conn, actor, 'ASSET_NETWORK_CHECK_REQUESTED', object_id, {'job_id': job_id, 'kind': kind})
    return public_job(conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job_id,)).fetchone())


def request_job(kind, object_id, body, actor):
    with assets.write_transaction() as conn:
        row = scope_row(conn, kind, object_id)
        if row['generation'] != body.expected_generation:
            raise HTTPException(409, 'Configuration generation changed.')
        return enqueue(conn, kind, object_id, row, actor, 'manual', body.idempotency_key)


def list_jobs(kind, object_id=None, limit=50, offset=0):
    clauses, args = ['kind=?'], [kind]
    if object_id is not None:
        column = 'asset_id' if kind == 'monitor' else 'profile_id'
        clauses.append(column + '=?'); args.append(object_id)
    with get_connection() as conn:
        total = conn.execute('SELECT COUNT(*) FROM asset_network_jobs WHERE ' + ' AND '.join(clauses), args).fetchone()[0]
        rows = conn.execute('SELECT * FROM asset_network_jobs WHERE ' + ' AND '.join(clauses) + ' ORDER BY id DESC LIMIT ? OFFSET ?', (*args, limit, offset)).fetchall()
    return {'items': [public_job(row) for row in rows], 'total': total, 'limit': limit, 'offset': offset}


def get_job(job_id, kind, asset_id=None):
    with get_connection() as conn:
        row = conn.execute('SELECT * FROM asset_network_jobs WHERE id=? AND kind=?', (job_id, kind)).fetchone()
        if row is None or (asset_id is not None and row['asset_id'] != asset_id):
            raise HTTPException(404, 'Network job not found.')
        return public_job(row)


def cancel_job(job_id, actor):
    with assets.write_transaction() as conn:
        row = conn.execute("SELECT * FROM asset_network_jobs WHERE id=? AND kind='discovery'", (job_id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'Discovery run not found.')
        if row['status'] in ('queued', 'running'):
            conn.execute("UPDATE asset_network_jobs SET status='cancelled',completed_at=?,result_json=? WHERE id=?",
                         (time.time(), assets.canonical({'reason': 'cancelled_by_actor'}), job_id))
            assets.audit(conn, actor, 'ASSET_DISCOVERY_CANCELLED', row['profile_id'], {'job_id': job_id})
        return public_job(conn.execute('SELECT * FROM asset_network_jobs WHERE id=?', (job_id,)).fetchone())


def archive_monitors(conn, asset_id, actor):
    row = conn.execute('SELECT enabled FROM asset_monitor_configs WHERE asset_id=?', (asset_id,)).fetchone()
    if row:
        cancel_scope(conn, 'monitor', asset_id, 'asset_archived')
        conn.execute("UPDATE asset_monitor_configs SET enabled=0,next_due=NULL,generation=generation+1,row_version=row_version+1,updated_by=?,updated_at=? WHERE asset_id=?", (actor['username'], time.time(), asset_id))
        if row['enabled']:
            assets.audit(conn, actor, 'ASSET_MONITOR_DISABLED_BY_ARCHIVE', asset_id)


def state_after(previous, result, settings, now):
    state = dict(previous)
    outcome = result['outcome']
    state['latest'] = {**result, 'checked_at': now}
    if outcome == 'up':
        state.update(stable='up', failures=0, last_success=now, measured_at=now)
    elif outcome == 'down':
        failures = state.get('failures', 0) + 1
        state.update(failures=failures, last_failure=now, measured_at=now)
        if failures >= settings['failure_threshold']:
            state['stable'] = 'down'
    else:
        state['failures'] = 0
    return state
