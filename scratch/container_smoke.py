"""Smoke-test a built image with two workers and a disposable persistent volume.

Usage: python -m scratch.container_smoke cyberdash:review-fixes
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


def main(image):
    name = "cyberdash-smoke-" + uuid.uuid4().hex[:12]
    volume = name + "-data"
    env = {**os.environ, "JWT_SECRET_KEY": secrets.token_hex(32)}
    docker("volume", "create", volume)

    def start():
        docker("run", "-d", "--name", name, "-e", "JWT_SECRET_KEY", "-v", volume + ":/app/data",
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
        assert requests.post(url + "/api/auth/login", json={"username": "smoke_owner", "password": password}, timeout=10).status_code == 200
        print("Container smoke passed: non-root runtime, two workers, health, auth, rate limits, audit concurrency and persistence across replacement.")
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "volume", "rm", volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "cyberdash:review-fixes")
