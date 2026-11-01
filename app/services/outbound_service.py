"""Outbound HTTP with public-only DNS, connection pinning and bounded redirects.

The socket connects to a validated numeric address. HTTP Host and TLS SNI still
use the original origin, avoiding the DNS-check/connection race (rebinding).
"""

import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from app.config import HTTP_TIMEOUT_SECONDS


def public_addresses(host: str, port: int) -> list[str]:
    if "%" in host:
        raise ValueError("Scoped network addresses are prohibited.")
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            addresses = list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except OSError as exc:
            raise ValueError("Destination DNS resolution failed.") from exc
    if not addresses:
        raise ValueError("Destination has no public addresses.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        mapped = getattr(ip, "ipv4_mapped", None)
        if not ip.is_global or ip.is_multicast or (mapped and not mapped.is_global):
            raise ValueError("Private, special-use and internal network addresses are prohibited.")
    return addresses


def validate_external_url(url: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Only HTTP(S) URLs without embedded credentials are allowed.")
        if any(ord(c) < 33 for c in url) or "\\" in url:
            raise ValueError("Invalid URL characters.")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid destination port.")
        public_addresses(parsed.hostname, port)
        return parsed.hostname, port
    except (TypeError, AttributeError) as exc:
        raise ValueError("Invalid URL.") from exc


def is_safe_external_url(url: str) -> tuple[bool, str]:
    try:
        validate_external_url(url)
        return True, ""
    except (ValueError, OSError) as exc:
        return False, str(exc)


class PublicNetworkBackend(httpcore.SyncBackend):
    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = public_addresses(host, port)
        last_error = None
        for address in addresses:
            try:
                return super().connect_tcp(address, port, timeout, local_address, socket_options)
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        raise httpcore.ConnectError("Unable to connect to a public destination.") from last_error


class PublicHTTPTransport(httpx.HTTPTransport):
    def __init__(self):
        super().__init__(trust_env=False)
        # HTTPX does not expose a network_backend constructor argument; the
        # pinned httpcore pool supplies it while preserving HTTPX's adapter.
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            network_backend=PublicNetworkBackend(),
            max_connections=5,
            max_keepalive_connections=0,
        )


def safe_request(method: str, url: str, *, json=None, max_bytes: int = 4 * 1024 * 1024,
                 allow_redirects: bool = False) -> httpx.Response:
    """Fetch bounded content; validate every redirect and every socket connection."""
    with httpx.Client(transport=PublicHTTPTransport(), trust_env=False, timeout=HTTP_TIMEOUT_SECONDS) as client:
        for redirect in range(4):
            validate_external_url(url)
            with client.stream(method, url, json=json) as response:
                if response.is_redirect and allow_redirects:
                    if redirect == 3 or "location" not in response.headers:
                        raise ValueError("Too many or invalid redirects.")
                    target = urljoin(url, response.headers["location"])
                    if urlsplit(url).scheme == "https" and urlsplit(target).scheme != "https":
                        raise ValueError("HTTPS downgrade redirects are prohibited.")
                    url = target
                    continue
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > max_bytes:
                        raise ValueError("Outbound response exceeds the size limit.")
                return httpx.Response(response.status_code, headers=response.headers,
                                      content=bytes(content), request=response.request)
    raise ValueError("Redirect limit exceeded.")
