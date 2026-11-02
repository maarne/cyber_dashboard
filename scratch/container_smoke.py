"""Smoke-test a built image with two workers and a disposable persistent volume.

Usage: python -m scratch.container_smoke cyberdash:asset-network [--assets | --network]
Only the uniquely named test container/volume created here are removed.
"""

import os
import secrets
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import requests


def docker(*args, env=None):
    return subprocess.check_output(["docker", *args], env=env, text=True).strip()


def main(image, assets=False, network_features=False):
    assets = assets or network_features
    name = "cyberdash-smoke-" + uuid.uuid4().hex[:12]
    volume = name + "-data"
    env = {**os.environ, "JWT_SECRET_KEY": secrets.token_hex(32), "FEATURE_ASSET_PRIORITIZATION": str(assets).lower(),
           'FEATURE_ASSET_MONITORING': str(network_features).lower(), 'FEATURE_ASSET_DISCOVERY': str(network_features).lower(),
           'ASSET_PROBE_ALLOWED_CIDRS': ''}
    docker("volume", "create", volume)

    def start():
        docker("run", "-d", "--name", name, "-e", "JWT_SECRET_KEY", "-e", "FEATURE_ASSET_PRIORITIZATION",
               '-e', 'FEATURE_ASSET_MONITORING', '-e', 'FEATURE_ASSET_DISCOVERY', '-e', 'ASSET_PROBE_ALLOWED_CIDRS', '-v', volume + ":/app/data",
               "-p", "127.0.0.1::8000", image, env=env)
        address = docker("port", name, "8000/tcp").splitlines()[0]
        url = "http://" + address
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                if requests.get(url + "/api/health", timeout=2).status_code == 200:
                    return url
            except requests.RequestException:
                pass
            time.sleep(0.25)
        raise RuntimeError("Container did not become healthy.\n" + docker("logs", name))

    try:
        url = start()
        assert docker("exec", name, "id", "-u") == "10001"
        assert requests.get(url + "/api/ready", timeout=5).json()["setup_required"]
        password = secrets.token_urlsafe(20) + "Aa1!"
        session = requests.Session()
        assert session.post(url + "/api/setup", json={"username": "smoke_owner", "password": password}, timeout=10).status_code == 201
        if assets:
            csrf = session.get(url + "/api/assets/session", timeout=5).json()["csrf_token"]
            asset_headers = {"Origin": url, "X-CSRF-Token": csrf}
            assert session.post(url + "/api/assets", json={"external_id": "smoke", "name": "Smoke inventory"}, timeout=5).status_code == 403
            response = session.post(url + "/api/assets", json={"external_id": "smoke", "name": "Smoke inventory"}, headers=asset_headers, timeout=5)
            assert response.status_code == 201, response.text
            asset_id = response.json()["id"]
            response = session.post(url + f"/api/assets/{asset_id}/cves", json={"cve_id": "CVE-2026-10000", "evidence_note": "Synthetic smoke fixture"}, headers=asset_headers, timeout=5)
            assert response.status_code == 201, response.text
            queue = session.get(url + "/api/priorities", timeout=5).json()
            assert queue["total"] == 1 and queue["items"][0]["score"] is None
            def edit_inventory(number):
                return session.patch(url + f"/api/assets/{asset_id}", json={"expected_version": 1, "name": f"Concurrent {number}"}, headers=asset_headers, timeout=10).status_code
            with ThreadPoolExecutor(max_workers=2) as executor:
                assert sorted(executor.map(edit_inventory, range(2))) == [200, 409]
            if network_features:
                assert not session.get(url + '/api/asset-monitoring/capabilities', timeout=5).json()['scope']['configured']
                response = session.put(url + f'/api/assets/{asset_id}/monitoring', json={'expected_version': 0, 'target': 'probe.example.test'}, headers=asset_headers, timeout=10)
                assert response.status_code == 200, response.text
                assert response.json()['state']['availability'] == 'disabled'
                response = session.post(url + '/api/asset-discovery/profiles', json={'name': 'Disabled smoke profile', 'networks': ['192.168.50.0/30']}, headers=asset_headers, timeout=10)
                assert response.status_code == 201, response.text
                profile_id = response.json()['id']
                assert session.post(url + f'/api/asset-discovery/profiles/{profile_id}/runs', json={'expected_generation': 1, 'idempotency_key': 'smoke-disabled'}, headers=asset_headers, timeout=5).status_code == 409
                response = session.patch(url + f'/api/asset-discovery/profiles/{profile_id}', json={'expected_version': 1, 'name': 'Denied enable', 'networks': ['192.168.50.0/30'], 'enabled': True, 'authorized': True}, headers=asset_headers, timeout=5)
                assert response.status_code == 422, response.text
                assert session.get(url + '/api/asset-discovery/runs', timeout=5).json()['total'] == 0
                assert session.get(url + '/asset-discovery', timeout=5).status_code == 200
        else:
            assert session.get(url + "/api/assets", timeout=5).status_code == 404
        for _ in range(10):
            assert session.get(url + "/api/users", timeout=5).status_code == 200
        token = session.post(url + "/api/tokens", json={"name": "smoke", "rate_limit_per_min": 1}, timeout=5).json()["token"]
        headers = {"X-API-Key": token}
        assert requests.get(url + "/api/summary", headers=headers, timeout=5).status_code == 200
        assert requests.get(url + "/api/summary", headers=headers, timeout=5).status_code == 429

        def login(_):
            return requests.post(url + "/api/auth/login", json={"username": "smoke_owner", "password": password}, timeout=20).status_code
        with ThreadPoolExecutor(max_workers=6) as executor:
            assert all(code == 200 for code in executor.map(login, range(6)))
        assert session.get(url + "/api/audit-logs/verify", timeout=10).json()["is_valid"]
        old_cookie = session.cookies.get("access_token")
        assert session.post(url + "/api/auth/logout", timeout=5).status_code == 200
        assert requests.get(url + "/api/users", cookies={"access_token": old_cookie}, timeout=5).status_code == 401

        # Replace the container, not merely its processes: only volume data survives.
        docker("rm", "-f", name)
        url = start()
        assert not requests.get(url + "/api/ready", timeout=5).json()["setup_required"]
        restored = requests.Session()
        assert restored.post(url + "/api/auth/login", json={"username": "smoke_owner", "password": password}, timeout=10).status_code == 200
        if assets:
            assert restored.get(url + "/api/priorities", timeout=5).json()["total"] == 1
            assert restored.get(url + "/api/audit-logs/verify", timeout=10).json()["is_valid"]
        if network_features:
            assert restored.get(url + f'/api/assets/{asset_id}/monitoring', timeout=5).json()['state']['availability'] == 'disabled'
            assert len(restored.get(url + '/api/asset-discovery/profiles', timeout=5).json()['items']) == 1
            assert restored.get(url + '/api/asset-discovery/runs', timeout=5).json()['total'] == 0
        print("Container smoke passed: non-root runtime, two workers, health, auth, rate limits, audit concurrency and persistence across replacement.")
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "volume", "rm", volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "cyberdash:asset-network", "--assets" in sys.argv[2:], '--network' in sys.argv[2:])
