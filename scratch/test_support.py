"""Import BEFORE app modules. Each test process owns its temporary database.

Run suites with ``python -m scratch.run_tests``; suites intentionally execute
in separate interpreters so module-level application settings cannot leak.
"""

import atexit
import os
import secrets
import socket
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if "app.config" in sys.modules:
    raise RuntimeError("Test isolation must be configured before importing the application.")
_sandbox = tempfile.TemporaryDirectory(prefix="cyberdash-test-")
atexit.register(_sandbox.cleanup)
os.environ["DATABASE_PATH"] = str(Path(_sandbox.name) / "test.db")
os.environ["JWT_SECRET_KEY"] = secrets.token_hex(32)
os.environ.pop("ENV", None)

# A forgotten mock must never contact real feeds, webhooks or enrichment APIs.
_network_guard = patch("httpx.HTTPTransport.handle_request", side_effect=RuntimeError("Outbound HTTP must be mocked in tests."))
_network_guard.start()
atexit.register(_network_guard.stop)


def _fixture_dns(host, port, *args, **kwargs):
    # Deterministic DNS fixtures: URL validation must not depend on Internet DNS.
    address = "127.0.0.1" if host in ("localhost", "metadata.google.internal", "instance-data") else "8.8.8.8"
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]


for target, replacement in (
    ("socket.getaddrinfo", {"side_effect": _fixture_dns}),
    ("socket.gethostbyaddr", {"side_effect": OSError("Mock reverse DNS unavailable")}),
    ("socket.gethostbyname_ex", {"side_effect": OSError("Mock DNS unavailable")}),
):
    guard = patch(target, **replacement)
    guard.start()
    atexit.register(guard.stop)


def assert_test_database():
    from app.database import DATABASE_PATH
    if Path(DATABASE_PATH).resolve().parent != Path(_sandbox.name).resolve():
        raise RuntimeError("Refusing to run tests against a non-sandbox database.")
