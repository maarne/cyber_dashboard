"""In-process adapter for older requests-style checks; never opens a live server."""

from urllib.parse import urlsplit
from scratch import test_support
from fastapi.testclient import TestClient
from app.main import app
from app.database import initialize_database
from app.services.auth_service import create_access_token, create_user

test_support.assert_test_database()
initialize_database()
create_user("admin", "cyberdash123!", "admin")


class SandboxSession(TestClient):
    def __init__(self):
        super().__init__(app)

    def request(self, method, url, **kwargs):
        test_support.assert_test_database()
        if "allow_redirects" in kwargs:
            kwargs["follow_redirects"] = kwargs.pop("allow_redirects")
        parts = urlsplit(str(url))
        if parts.netloc and parts.netloc not in ("127.0.0.1:8000", "testserver"):
            raise RuntimeError("Legacy tests may only target the in-process sandbox.")
        return super().request(method, parts.path + ("?" + parts.query if parts.query else ""), **kwargs)


class RequestsSandbox:
    Session = SandboxSession

    @staticmethod
    def get(url, **kwargs):
        with authenticated_session() as client:
            return client.get(url, **kwargs)


requests = RequestsSandbox()


def authenticated_session():
    client = SandboxSession()
    client.cookies.set("access_token", create_access_token("admin"))
    return client
