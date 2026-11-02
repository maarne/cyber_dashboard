"""Authorized, append-only server-captured IOC results. Never accepts client evidence."""
import hashlib
import ipaddress
import json
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from fastapi import HTTPException
from app.database import get_connection
from app.services import ioc_service
from app.services.case_common import actor_key, actor_values, audit, canonical, now, write_transaction

MAX_SNAPSHOT_BYTES = 256 * 1024
MAX_STORAGE_BYTES = 50 * 1024 * 1024
MAX_SNAPSHOTS = 1000
SENSITIVE = re.compile(r'password|passwd|secret|token|api.?key|access.?key|private.?key|credential|session|authorization|cookie|mfa', re.I)


def safe_url(value):
    try:
        parsed = urlsplit(value)
        return (parsed.scheme in ('http', 'https') and bool(parsed.hostname) and not parsed.username and not parsed.password
                and not any(SENSITIVE.search(k) for k, _ in parse_qsl(parsed.query)) and not parsed.fragment)
    except ValueError:
        return False


def normalize(indicator):
    value = indicator.strip()
    if any(ord(c) < 32 for c in value):
        raise HTTPException(422, 'Control characters are not valid indicators.')
    kind = ioc_service.classify_ioc(value.rstrip('.') if '://' not in value else value)
    if kind == 'unknown':
        raise HTTPException(422, 'Use an IP, domain, HTTP(S) URL or MD5/SHA1/SHA256 hash.')
    if kind in ('ipv4', 'ipv6'):
        value = str(ipaddress.ip_address(value))
    elif kind in ('domain', 'md5', 'sha1', 'sha256'):
        value = value.lower().rstrip('.')
    elif kind == 'url':
        if not safe_url(value):
            raise HTTPException(422, 'Use an HTTP(S) URL without credentials, sensitive query parameters or a fragment.')
        parts = urlsplit(value)
        # Access .port to reject malformed authority syntax without resolving it.
        try:
            parts.port
        except ValueError as exc:
            raise HTTPException(422, 'Invalid URL port.') from exc
        value = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or '/', parts.query, ''))
    return value, kind


def sanitize(value, depth=0):
    if depth > 12:
        raise HTTPException(422, 'Evidence nesting exceeds the supported limit.')
    if isinstance(value, dict):
        return {k: sanitize(v, depth+1) for k, v in value.items() if k == 'token_id' or not SENSITIVE.search(k)}
    if isinstance(value, list):
        return [sanitize(v, depth+1) for v in value]
    if isinstance(value, str) and value.startswith(('http://', 'https://')) and not safe_url(value):
        return '[unsafe or credential-bearing URL omitted]'
    return value


def snapshot_record(row):
    valid = hashlib.sha256(row['payload_json'].encode()).hexdigest() == row['sha256']
    try:
        payload = json.loads(row['payload_json'])
        if not isinstance(payload, dict):
            payload = None; valid = False
        elif (payload.get('captured_at') != row['captured_at'] or payload.get('schema_version') != row['schema_version']
              or payload.get('dossier', {}).get('indicator') != row['indicator']
              or payload.get('dossier', {}).get('ioc_type') != row['indicator_type']
              or payload.get('captured_by', {}).get('name') != row['actor_name']):
            valid = False
    except (ValueError, TypeError, AttributeError):
        payload = None; valid = False
    return {**{k: row[k] for k in ('id', 'indicator', 'indicator_type', 'actor_user_id', 'actor_token_id', 'actor_name',
                                  'captured_at', 'schema_version', 'sha256')},
            'integrity_valid': valid, 'warning': None if valid else 'INTEGRITY WARNING: stored evidence differs from its captured digest.',
            'evidence': payload}


def authorized_snapshot(conn, snapshot_id, actor, *, require_integrity=False):
    row = conn.execute('''SELECT s.* FROM investigation_snapshots s WHERE s.id=? AND
        (s.principal_key=? OR EXISTS(SELECT 1 FROM case_evidence e WHERE e.snapshot_id=s.id))''',
                       (snapshot_id, actor_key(actor))).fetchone()
    if not row:
        raise HTTPException(404, 'Captured investigation not found for this caller or a shared case.')
    record = snapshot_record(row)
    if require_integrity and not record['integrity_valid']:
        raise HTTPException(409, record['warning'])
    return record


def get_snapshot(snapshot_id, actor):
    with get_connection() as conn:
        return authorized_snapshot(conn, snapshot_id, actor)


def capture(model, actor):
    indicator, kind = normalize(model.indicator)
    # No DB write lock is held during optional enrichment.
    with get_connection() as conn:
        used = conn.execute('SELECT COUNT(*),COALESCE(SUM(payload_bytes),0) FROM investigation_snapshots').fetchone()
        if used[0] >= MAX_SNAPSHOTS or used[1] >= MAX_STORAGE_BYTES:
            raise HTTPException(409, 'Snapshot storage limit reached; export/back up and review retention.')
    dossier = ioc_service.investigate_ioc(indicator, local_only=model.local_only, save_history=False)
    dossier = {k: dossier[k] for k in ('indicator', 'ioc_type', 'verdict', 'threat_score', 'confidence', 'summary', 'threat_tags',
                                      'network', 'feed_matches', 'threat_actors', 'pivots', 'raw_details', 'sources') if k in dossier}
    captured_at = now()
    with get_connection() as conn:
        freshness = [dict(r) for r in conn.execute('SELECT source_name,last_fetch,last_success,status,record_count FROM fetch_log ORDER BY source_name LIMIT 100')]
    payload = canonical(sanitize({'schema_version': 1, 'captured_at': captured_at, 'captured_by': {
        'user_id': actor.get('user_id'), 'token_id': actor.get('token_id'), 'name': actor['username']},
        'privacy_mode': 'local_only' if model.local_only else 'existing_enrichment',
        'dossier': dossier, 'feed_state': freshness,
        'notice': 'Internal SOC evidence. Provider pivots are links, not queries. Missing checks remain unknown; a case conclusion is a separate human decision.'}))
    size = len(payload.encode())
    if size > MAX_SNAPSHOT_BYTES:
        raise HTTPException(413, 'Snapshot exceeds 256 KiB; nothing was stored or truncated.')
    with write_transaction() as conn:
        used = conn.execute('SELECT COUNT(*),COALESCE(SUM(payload_bytes),0) FROM investigation_snapshots').fetchone()
        if used[0] >= MAX_SNAPSHOTS or used[1] + size > MAX_STORAGE_BYTES:
            raise HTTPException(409, 'Snapshot storage limit reached; nothing was stored.')
        snapshot_id = conn.execute('''INSERT INTO investigation_snapshots(indicator,indicator_type,principal_key,
            actor_user_id,actor_token_id,actor_name,captured_at,payload_json,sha256,payload_bytes) VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (indicator, kind, actor_key(actor), *actor_values(actor), captured_at, payload, hashlib.sha256(payload.encode()).hexdigest(), size)).lastrowid
        history_id = conn.execute('''INSERT INTO investigation_history(indicator,indicator_type,verdict,threat_score,threat_tags,geo_country,
            actor_user_id,actor_token_id,actor_name,snapshot_id) VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (indicator, kind, dossier['verdict'], dossier['threat_score'], ', '.join(dossier.get('threat_tags', [])),
             dossier.get('network', {}).get('country', ''), *actor_values(actor), snapshot_id)).lastrowid
        audit(conn, actor, 'INVESTIGATION_CAPTURED', snapshot_id, {'local_only': model.local_only, 'snapshot_id': snapshot_id})
        snapshot = authorized_snapshot(conn, snapshot_id, actor)
    from app.services.case_service import list_cases
    return {'snapshot': snapshot, 'history_id': history_id,
            'matching_cases': list_cases(indicator=indicator, active_only=True, limit=10)['items']}
