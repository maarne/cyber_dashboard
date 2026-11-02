"""Bounded case read/export measurements; isolated synthetic fixtures, no network."""
from scratch import test_support
import hashlib
import json
import time
from app.database import initialize_database, get_connection
from app.models.case_schemas import CaseCreate
from app.services import auth_service as auth, case_service as cases
from app.services.case_common import actor_key, actor_values, canonical, now


def main():
    initialize_database()
    auth.complete_initial_setup('fixture', auth.generate_secure_random_password(18))
    actor = {'username': 'fixture', 'role': 'admin', 'user_id': auth.get_user_by_username('fixture')['id']}
    ids = [cases.create(CaseCreate(title=f'Synthetic case {i}'), actor)['id'] for i in range(200)]
    timestamp = now()
    with get_connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        for i in range(1000):
            indicator = f'fixture-{i}.example.test'
            payload = canonical({'schema_version': 1, 'captured_at': timestamp, 'captured_by': {'name': 'fixture'},
                'privacy_mode': 'local_only', 'dossier': {'indicator': indicator, 'ioc_type': 'domain', 'verdict': 'UNKNOWN',
                'raw_details': {'synthetic_fixture': 'x'*50000}, 'sources': {'dns': {'status': 'not_queried'}}}})
            snapshot_id = conn.execute('''INSERT INTO investigation_snapshots(indicator,indicator_type,principal_key,actor_user_id,actor_token_id,
                actor_name,captured_at,payload_json,sha256,payload_bytes) VALUES (?,'domain',?,?,?,?,?,?,?,?)''',
                (indicator, actor_key(actor), *actor_values(actor), timestamp, payload, hashlib.sha256(payload.encode()).hexdigest(), len(payload.encode()))).lastrowid
            case_id = ids[0] if i < 25 else ids[1+(i-25)%199]
            conn.execute('INSERT INTO case_evidence(case_id,snapshot_id,actor_user_id,actor_token_id,actor_name,created_at) VALUES (?,?,?,?,?,?)',
                         (case_id, snapshot_id, *actor_values(actor), timestamp))
        for case_id in ids:
            for _ in range(200 if case_id == ids[0] else 2):
                conn.execute('INSERT INTO case_notes(case_id,body,actor_user_id,actor_token_id,actor_name,created_at) VALUES (?,?,?,?,?,?)',
                             (case_id, 'n'*(8000 if case_id == ids[0] else 1000), *actor_values(actor), timestamp))
        used = conn.execute('SELECT SUM(payload_bytes) FROM investigation_snapshots').fetchone()[0]
        assert used <= cases.LIMITS['snapshot_storage_bytes']
    metrics = {}
    for label, fn in (
        ('list_50_seconds', lambda: cases.list_cases(status='open', limit=50)),
        ('evidence_page_10_seconds', lambda: cases.collection(ids[0], 'evidence', limit=10)),
        ('max_case_json_export_seconds', lambda: cases.export_case(ids[0], actor, 'json')),
        ('max_case_markdown_export_seconds', lambda: cases.export_case(ids[0], actor, 'markdown')),
    ):
        start = time.perf_counter(); result = fn(); metrics[label] = round(time.perf_counter()-start, 4)
        if 'export' in label: metrics[label.replace('_seconds', '_bytes')] = len(result[0].encode())
    with get_connection() as conn:
        plans = [r[3] for r in conn.execute("EXPLAIN QUERY PLAN SELECT id FROM cases WHERE is_archived=0 AND status='open' ORDER BY id DESC LIMIT 50")]
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert not conn.execute('PRAGMA foreign_key_check').fetchall()
    print(json.dumps({'synthetic_only': True, 'cases': 200, 'snapshots': 1000, 'snapshot_payload_bytes': used,
                      'largest_case': {'snapshots': 25, 'notes': 200, 'characters_per_note': 8000},
                      'metrics': metrics, 'query_plan': plans,
                      'notice': 'Local bookkeeping/read/export measurement, not F1 latency or a concurrency/SLA guarantee.'}, indent=2))


if __name__ == '__main__': main()
