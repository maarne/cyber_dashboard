"""Isolated bookkeeping measurements; mocked probes, never real networks."""
from scratch import test_support
import os
os.environ.update(FEATURE_ASSET_PRIORITIZATION='true', FEATURE_ASSET_MONITORING='true', FEATURE_ASSET_DISCOVERY='true',
                  ASSET_PROBE_ALLOWED_CIDRS='192.168.48.0/20', ASSET_PROBE_RATE_PER_MINUTE='600')

import json
import time
from unittest.mock import patch
from app.database import initialize_database, get_connection
from app.models.asset_network_schemas import MonitorSettings
from app.services import asset_service as assets, asset_network_service as network, asset_network_worker as worker, asset_probe_service as probes
from app.services.asset_probe_policy import ProbePolicy
from app.services import auth_service as auth


def main():
    initialize_database()
    auth.complete_initial_setup('fixture', auth.generate_secure_random_password(18))
    actor = {'username': 'fixture', 'role': 'admin', 'user_id': auth.get_user_by_username('fixture')['id']}
    start = time.perf_counter()
    targets = ProbePolicy().targets(['192.168.48.0/20'], [])
    enumeration = time.perf_counter() - start
    for index in range(100):
        a = assets.create_asset({'external_id': f'fixture-{index}', 'name': f'Fixture {index}'}, actor)
        network.save_monitor(a['id'], MonitorSettings(expected_version=0, target=targets[index], enabled=True, authorized=True, scheduled=True), actor)
    with get_connection() as conn: conn.execute('UPDATE asset_monitor_configs SET next_due=0')
    start = time.perf_counter()
    for _ in range(5): worker.schedule_due()
    with patch.object(probes, 'check', return_value={'outcome': 'up', 'reason': 'mocked_measurement'}):
        completed = 0
        while (job := worker.claim_job()) is not None:
            worker.execute_job(job); completed += 1
    elapsed = time.perf_counter() - start
    with get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM asset_network_jobs WHERE status='completed'").fetchone()[0] == 100
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        db_bytes = conn.execute('PRAGMA page_count').fetchone()[0] * conn.execute('PRAGMA page_size').fetchone()[0]
    print(json.dumps({'network_probes': 'mocked', 'configured_monitors': 100, 'completed': completed,
                      'schedule_and_record_seconds': round(elapsed,3), 'authorized_4096_range_enumeration_seconds': round(enumeration,3),
                      'enumerated_host_addresses': len(targets), 'isolated_database_bytes': db_bytes,
                      'notice': 'Bookkeeping only; not network scan throughput, F1 latency, or a load/uptime guarantee.'}, indent=2))


if __name__ == '__main__':
    main()
