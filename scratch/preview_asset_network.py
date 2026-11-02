"""Isolated localhost UI preview. ALL probes and DNS are simulated, never real."""
from scratch import test_support

import os
os.environ.update(FEATURE_ASSET_PRIORITIZATION='true', FEATURE_ASSET_MONITORING='true', FEATURE_ASSET_DISCOVERY='true',
                  ASSET_PROBE_ALLOWED_CIDRS='192.168.50.0/24,192.168.51.0/24', PUBLIC_BASE_URL='http://localhost:8766')

from app.database import initialize_database
from app.models.asset_network_schemas import DiscoverySettings, CheckRequest
from app.services import auth_service as auth, asset_service as assets, asset_probe_service as probes
from app.services import asset_network_service as network, asset_network_worker as worker


def forbidden(*args, **kwargs):
    raise AssertionError('Real subprocesses/DNS are forbidden in this preview.')


probes.bounded_process = forbidden
probes.check = lambda settings, ip, cancelled: {'outcome': 'up', 'reason': 'SIMULATED_success', 'address': ip, 'latency_ms': 2.0}
probes.discover = lambda ips, settings, cancelled: [{'address': ip, 'evidence': 'SIMULATED_discovery_response'} for ip in ips]
probes.reverse_name = lambda ip, *args, **kwargs: [{'name': 'mock-' + ip.replace('.', '-') + '.example.test', 'source': 'SIMULATED_PTR', 'forward_confirmed': False}]
probes.capabilities = lambda: {'https': True, 'http': True, 'tcp': True, 'icmp': True, 'discovery': True,
                              'note': 'MOCK PREVIEW ONLY: all probes and DNS are simulated. No real target traffic.'}

initialize_database()
auth.complete_initial_setup('mock_preview', 'Preview-Only#2026A')
actor = {'username': 'mock_preview', 'role': 'admin', 'user_id': auth.get_user_by_username('mock_preview')['id']}
assets.create_asset({'external_id': 'mock-router', 'name': 'MOCK preview router'}, actor)
profile = network.save_profile(None, DiscoverySettings(name='MOCK multi-network discovery', networks=['192.168.50.0/30', '192.168.51.0/30'],
                    enabled=True, authorized=True, resolve_names=True), actor)
network.request_job('discovery', profile['id'], CheckRequest(expected_generation=1, idempotency_key='mock-preview-seed'), actor)
worker.execute_job(worker.claim_job())

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('app.main:app', host='127.0.0.1', port=8766)
