"""Feature-scoped transport guards; never buffers an unbounded request body."""

import hashlib
import hmac
from urllib.parse import urlsplit

from fastapi import HTTPException
from starlette.responses import JSONResponse

from app.config import FEATURE_ASSET_PRIORITIZATION, JWT_SECRET_KEY, PUBLIC_BASE_URL


def is_asset_path(path):
    return any(path == p or path.startswith(p + "/") for p in
               ("/assets", "/priorities", "/api/assets", "/api/asset-assessments", "/api/priorities"))


def csrf_token(request):
    session = request.cookies.get("access_token", "")
    return hmac.new(JWT_SECRET_KEY.encode(), b"asset-csrf-v1:" + session.encode(), hashlib.sha256).hexdigest()


def origin(value):
    try:
        url = urlsplit(value)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
            return None
        return url.scheme, url.hostname.lower(), url.port or (443 if url.scheme == "https" else 80)
    except ValueError:
        return None


def protect_mutation(request, actor):
    if actor.get("auth_method") != "cookie":
        return
    supplied = request.headers.get("X-CSRF-Token", "")
    if not hmac.compare_digest(supplied.encode(), csrf_token(request).encode()):
        raise HTTPException(403, "A valid session CSRF token is required.")
    expected = origin(PUBLIC_BASE_URL or str(request.base_url))
    supplied_origin = request.headers.get("origin") or request.headers.get("referer", "")
    if expected is None or origin(supplied_origin) != expected:
        raise HTTPException(403, "A trusted same-origin request is required.")


class AssetTransportMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not is_asset_path(scope["path"]):
            return await self.app(scope, receive, send)

        async def private_send(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in (b"cache-control", b"pragma")]
                message = {**message, "headers": headers + [(b"cache-control", b"no-store, private"), (b"pragma", b"no-cache")]}
            await send(message)

        if not FEATURE_ASSET_PRIORITIZATION:
            return await JSONResponse({"detail": "Not found"}, 404)(scope, receive, private_send)
        if scope["method"] not in ("GET", "HEAD", "OPTIONS"):
            # JSON escaping can expand a 1 MiB CSV up to sixfold.
            maximum = 6 * 1048576 + 65536 if scope["path"] == "/api/assets/import/preview" else 65536
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > maximum:
                    return await JSONResponse({"detail": "Request body too large."}, 413)(scope, receive, private_send)
                if not message.get("more_body", False):
                    break
            delivered = False

            async def bounded_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            return await self.app(scope, bounded_receive, private_send)
        return await self.app(scope, receive, private_send)
