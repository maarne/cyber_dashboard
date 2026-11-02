"""Candidate review and atomic, selective import. Never sends network traffic."""
import hashlib
import ipaddress
import json
import secrets
import time

from fastapi import HTTPException

from app import config
from app.database import get_connection
from app.services import asset_service as assets
from app.services.asset_network_service import policy


def candidates(*, search='', profile_id=None, network='', review='new', limit=50, offset=0):
    clauses, args = ['1=1'], []
    if search:
        clauses.append("(c.address LIKE ? ESCAPE '\\' OR c.hostname LIKE ? ESCAPE '\\')")
        args.extend([assets.literal_like(search)] * 2)
    if profile_id is not None:
        clauses.append('EXISTS(SELECT 1 FROM asset_discovery_observations o WHERE o.candidate_id=c.id AND o.profile_id=?)')
        args.append(profile_id)
    if network:
        try:
            network = str(ipaddress.ip_network(network))
        except ValueError as exc:
            raise HTTPException(422, 'Network filter must be a canonical CIDR.') from exc
        clauses.append("EXISTS(SELECT 1 FROM asset_discovery_observations o,json_each(o.snapshot_json,'$.networks') n WHERE o.candidate_id=c.id AND n.value=?)")
        args.append(network)
    if review == 'new':
        clauses.append('c.is_ignored=0 AND c.imported_asset_id IS NULL')
    elif review == 'ignored':
        clauses.append('c.is_ignored=1')
    elif review == 'imported':
        clauses.append('c.imported_asset_id IS NOT NULL')
    clause = ' AND '.join(clauses)
    with get_connection() as conn:
        total = conn.execute('SELECT COUNT(*) FROM asset_discovery_candidates c WHERE ' + clause, args).fetchone()[0]
        rows = conn.execute('SELECT c.* FROM asset_discovery_candidates c WHERE ' + clause + ' ORDER BY c.last_seen DESC,c.id DESC LIMIT ? OFFSET ?', (*args, limit, offset)).fetchall()
        items = []
        for row in rows:
            observation = conn.execute('SELECT id,job_id,profile_id,observed_at,snapshot_json FROM asset_discovery_observations WHERE candidate_id=? ORDER BY id DESC LIMIT 1', (row['id'],)).fetchone()
            matches = [dict(r) for r in conn.execute('''SELECT DISTINCT a.id,a.name,a.row_version,a.is_archived FROM asset_addresses d
                JOIN assets a ON a.id=d.asset_id WHERE d.address=? AND d.scope=? LIMIT 20''', (row['address'], row['scope']))]
            observation_data = {k: observation[k] for k in ('id', 'job_id', 'profile_id', 'observed_at')} if observation else None
            items.append({**dict(row), 'names': json.loads(row['names_json']), 'observation': observation_data,
                          'networks': json.loads(observation['snapshot_json']).get('networks', []) if observation else [],
                          'possible_matches': matches})
    return {'items': items, 'total': total, 'limit': limit, 'offset': offset}


def review_candidate(candidate_id, body, actor):
    with assets.write_transaction() as conn:
        row = conn.execute('SELECT * FROM asset_discovery_candidates WHERE id=?', (candidate_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'Candidate not found.')
        assets.check_version(row, body.expected_version)
        conn.execute('UPDATE asset_discovery_candidates SET is_ignored=?,row_version=row_version+1 WHERE id=?', (int(body.ignored), candidate_id))
        if body.reopen_import:
            conn.execute('UPDATE asset_discovery_candidates SET imported_asset_id=NULL,needs_review=1 WHERE id=?', (candidate_id,))
        assets.audit(conn, actor, 'ASSET_DISCOVERY_REVIEWED', candidate_id, {'ignored': body.ignored, 'reopen_import': body.reopen_import})
    return {'reviewed': True}


def _selected(conn, item):
    row = conn.execute('SELECT * FROM asset_discovery_candidates WHERE id=?', (item['candidate_id'],)).fetchone()
    obs = conn.execute('SELECT * FROM asset_discovery_observations WHERE id=? AND candidate_id=?', (item['observation_id'], item['candidate_id'])).fetchone()
    if not row or not obs:
        raise HTTPException(404, 'Selected discovery observation not found.')
    if row['is_ignored'] or row['imported_asset_id'] is not None:
        raise HTTPException(409, 'Candidate already imported or ignored. Reload review results.')
    if obs['observed_at'] < time.time() - 86400:
        raise HTTPException(409, 'Observation is older than 24 hours. Rescan or use manual inventory entry.')
    if hashlib.sha256(obs['snapshot_json'].encode()).hexdigest() != obs['snapshot_hash']:
        raise HTTPException(409, 'Observation integrity mismatch.')
    profile = conn.execute('SELECT generation FROM asset_discovery_profiles WHERE id=?', (obs['profile_id'],)).fetchone()
    if not profile:
        raise HTTPException(409, 'Source profile is unavailable.')
    if json.loads(obs['snapshot_json']).get('generation') != profile['generation']:
        raise HTTPException(409, 'Source profile changed since this observation. Rescan first.')
    return row, obs, profile


def preview_import(model, actor):
    items = [item.model_dump(mode='json') for item in model.items]
    if len({item['candidate_id'] for item in items}) != len(items):
        raise HTTPException(422, 'Select a candidate only once.')
    p = policy()
    payload = []
    with assets.write_transaction() as conn:
        now = time.time()
        conn.execute('DELETE FROM asset_discovery_import_previews WHERE expires_at<? OR consumed_at IS NOT NULL', (now,))
        conn.execute('DELETE FROM asset_discovery_import_previews WHERE actor_key=?', (assets.actor_key(actor),))
        if conn.execute('SELECT COUNT(*) FROM asset_discovery_import_previews').fetchone()[0] >= 20:
            raise HTTPException(409, 'Too many pending discovery previews.')
        new_ids = set()
        for item in items:
            row, obs, profile = _selected(conn, item)
            p.approve(row['address'])
            if item['action'] == 'create':
                external_id = item['asset']['external_id']
                if external_id in new_ids or conn.execute('SELECT 1 FROM assets WHERE external_id=?', (external_id,)).fetchone():
                    raise HTTPException(409, 'External ID already exists; explicitly link to an asset or choose another ID.')
                new_ids.add(external_id)
            else:
                existing = assets.get_asset_record(conn, item['asset_id'], writable=True)
                assets.check_version(existing, item['expected_version'])
            payload.append({**item, 'identity_version': row['identity_version'], 'review_version': row['row_version'],
                            'snapshot_hash': obs['snapshot_hash'], 'profile_id': obs['profile_id'], 'profile_generation': profile['generation'],
                            'snapshot': json.loads(obs['snapshot_json'])})
        count = conn.execute('SELECT COUNT(*) FROM assets WHERE is_archived=0').fetchone()[0]
        if count + len(new_ids) > assets.MAX_ASSETS:
            raise HTTPException(409, 'Selected assets exceed the active inventory quota.')
        if conn.execute('SELECT COUNT(*) FROM asset_discovery_links').fetchone()[0] + len(items) > 20000:
            raise HTTPException(409, 'Retained discovery evidence limit reached (20000); export/back up and review storage policy.')
        if conn.execute('SELECT COUNT(*) FROM asset_addresses').fetchone()[0] + len(items) > 20000:
            raise HTTPException(409, 'Retained address limit reached (20000).')
        revision = conn.execute('SELECT revision FROM asset_inventory_state WHERE id=1').fetchone()[0]
        token = secrets.token_urlsafe(32); data = assets.canonical(payload)
        conn.execute('''INSERT INTO asset_discovery_import_previews(token_hash,actor_key,inventory_revision,payload_json,payload_hash,policy_hash,expires_at)
            VALUES (?,?,?,?,?,?,?)''', (hashlib.sha256(token.encode()).hexdigest(), assets.actor_key(actor), revision, data,
                                      hashlib.sha256(data.encode()).hexdigest(), p.fingerprint, now + 600))
        assets.audit(conn, actor, 'ASSET_DISCOVERY_IMPORT_PREVIEWED', 'discovery', {'selected': len(items)})
    return {'preview_token': token, 'expires_in_seconds': 600, 'items': payload,
            'summary': {'created': len(new_ids), 'linked': len(items) - len(new_ids)},
            'policy': 'Only selected rows; existing fields/assessments/monitor targets are preserved. Monitoring remains disabled.'}


def commit_import(token, actor):
    p = policy()
    with assets.write_transaction() as conn:
        key = hashlib.sha256(token.encode()).hexdigest()
        row = conn.execute('SELECT * FROM asset_discovery_import_previews WHERE token_hash=?', (key,)).fetchone()
        if not row or row['actor_key'] != assets.actor_key(actor):
            raise HTTPException(404, 'Discovery import preview not found for this caller.')
        revision = conn.execute('SELECT revision FROM asset_inventory_state WHERE id=1').fetchone()[0]
        if row['consumed_at'] or row['expires_at'] <= time.time() or revision != row['inventory_revision'] or row['policy_hash'] != p.fingerprint:
            raise HTTPException(409, 'Preview expired, used, or its inventory/policy changed. Preview again.')
        if hashlib.sha256(row['payload_json'].encode()).hexdigest() != row['payload_hash']:
            raise HTTPException(409, 'Preview integrity mismatch.')
        result, linked_changes = [], {}
        for item in json.loads(row['payload_json']):
            candidate, observation, profile = _selected(conn, item)
            if (candidate['identity_version'] != item['identity_version'] or candidate['row_version'] != item['review_version']
                    or profile['generation'] != item['profile_generation'] or observation['snapshot_hash'] != item['snapshot_hash']):
                raise HTTPException(409, 'Candidate identity/review/source profile changed. Preview again.')
            p.approve(candidate['address'])
            if item['action'] == 'create':
                asset_id = assets._create_asset(conn, item['asset'], actor)
            else:
                existing = assets.get_asset_record(conn, item['asset_id'], writable=True)
                assets.check_version(existing, item['expected_version'] + linked_changes.get(existing['id'], 0))
                asset_id = existing['id']
            snapshot = item['snapshot']
            conn.execute('''INSERT INTO asset_addresses(asset_id,address,hostname,scope,observed_at,provenance_json,created_by)
                VALUES (?,?,?,?,?,?,?) ON CONFLICT(asset_id,address,scope) DO UPDATE SET hostname=excluded.hostname,
                observed_at=excluded.observed_at,provenance_json=excluded.provenance_json,created_by=excluded.created_by''',
                         (asset_id, candidate['address'], snapshot.get('hostname'), candidate['scope'], observation['observed_at'],
                          assets.canonical({'observation_id': observation['id'], 'snapshot': snapshot, 'snapshot_hash': item['snapshot_hash']}), actor['username']))
            conn.execute('''INSERT INTO asset_discovery_links(asset_id,candidate_id,observation_id,snapshot_json,snapshot_hash,imported_at,imported_by)
                VALUES (?,?,?,?,?,?,?) ON CONFLICT(asset_id,snapshot_hash) DO NOTHING''',
                         (asset_id, candidate['id'], observation['id'], observation['snapshot_json'], observation['snapshot_hash'], time.time(), actor['username']))
            conn.execute('UPDATE asset_discovery_candidates SET imported_asset_id=?,needs_review=0,row_version=row_version+1 WHERE id=?', (asset_id, candidate['id']))
            if item['action'] == 'link':
                conn.execute('UPDATE assets SET row_version=row_version+1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?', (actor['username'], asset_id))
                linked_changes[asset_id] = linked_changes.get(asset_id, 0) + 1
            assets.bump_inventory(conn)
            assets.audit(conn, actor, 'ASSET_DISCOVERY_IMPORTED', asset_id, {'candidate_id': candidate['id'], 'action': item['action']})
            result.append({'candidate_id': candidate['id'], 'asset_id': asset_id, 'action': item['action']})
        conn.execute('UPDATE asset_discovery_import_previews SET consumed_at=?,payload_json=NULL WHERE token_hash=?', (time.time(), key))
        assets.audit(conn, actor, 'ASSET_DISCOVERY_IMPORT_COMMITTED', 'discovery', {'selected': len(result)})
        return {'items': result, 'monitoring_enabled': False}


def record_observation(conn, job, record, names, now):
    names = [{**name, 'observed_at': now} for name in names]
    address = record['address']; name = names[0]['name'] if names else None
    scope = config.ASSET_PROBE_SCOPE_LABEL
    row = conn.execute('SELECT * FROM asset_discovery_candidates WHERE scope=? AND address=?', (scope, address)).fetchone()
    if row:
        identity_changed = name is not None and row['hostname'] != name
        conn.execute('''UPDATE asset_discovery_candidates SET hostname=COALESCE(?,hostname),names_json=?,evidence=?,last_seen=?,
            identity_version=identity_version+?,row_version=row_version+?,needs_review=CASE WHEN ? THEN 1 ELSE needs_review END,
            imported_asset_id=CASE WHEN ? THEN NULL ELSE imported_asset_id END WHERE id=?''',
                     (name, assets.canonical(names) if names else row['names_json'], record['evidence'], now, int(identity_changed), int(identity_changed),
                      int(identity_changed), int(identity_changed), row['id']))
        candidate_id = row['id']
    else:
        if conn.execute('SELECT COUNT(*) FROM asset_discovery_candidates').fetchone()[0] >= 10000:
            raise HTTPException(409, 'Candidate staging capacity reached; review or clean expired data.')
        candidate_id = conn.execute('''INSERT INTO asset_discovery_candidates(scope,address,hostname,names_json,evidence,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?)''', (scope, address, name, assets.canonical(names), record['evidence'], now, now)).lastrowid
    ip = ipaddress.ip_address(address)
    networks = [n for n in json.loads(job['config_json'])['networks'] if ipaddress.ip_network(n).version == ip.version and ip in ipaddress.ip_network(n)]
    snapshot = assets.canonical({'address': address, 'hostname': name, 'names': names, 'evidence': record['evidence'], 'observed_at': now,
                                 'networks': networks,
                                 'scope': scope, 'job_id': job['id'], 'profile_id': job['profile_id'], 'generation': job['generation'],
                                 'dns_status': record.get('dns_status', 'not_requested')})
    if conn.execute('SELECT COUNT(*) FROM asset_discovery_observations').fetchone()[0] >= 50000:
        conn.execute('DELETE FROM asset_discovery_observations WHERE id IN (SELECT id FROM asset_discovery_observations ORDER BY id LIMIT 500)')
    conn.execute('INSERT INTO asset_discovery_observations(candidate_id,job_id,profile_id,observed_at,snapshot_json,snapshot_hash) VALUES (?,?,?,?,?,?)',
                 (candidate_id, job['id'], job['profile_id'], now, snapshot, hashlib.sha256(snapshot.encode()).hexdigest()))
