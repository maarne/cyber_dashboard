# ============================================================
# app/services/api_token_service.py — Developer API Token Engine
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides cryptographic token generation, verification, and
# lifecycle governance for developer and machine-to-machine
# integrations (SIEM, SOAR, scripts, SOC bots).
#
# SECURITY MODEL:
# ---------------
# - Tokens are prefixed with `cd_live_` for immediate secret scanning detection.
# - Secrets are generated via `secrets.token_hex(24)`.
# - Only SHA-256 hashes are persisted to the database. Raw tokens
#   are returned strictly once upon generation.
# - Dual authentication supported via:
#     X-API-Key: cd_live_...
#     Authorization: Bearer cd_live_...
# ============================================================

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from app.database import get_connection

TOKEN_PREFIX = "cd_live_"
VALID_ROLES = {"admin", "analyst", "viewer"}


class ApiRateLimitExceeded(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after


def hash_token(raw_token: str) -> str:
    """Compute SHA-256 digest of a raw API token string."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def generate_api_token(
    name: str,
    role: str = "viewer",
    created_by: str = "admin",
    expires_in_days: int | None = None,
    rate_limit: int = 60,
) -> tuple[str, dict]:
    """
    Generate a new scoped API token, storing its SHA-256 hash in SQLite.

    Returns:
        tuple: (raw_secret_token, token_metadata_dict)
    """
    cleaned_role = role.lower().strip() if role else "viewer"
    if cleaned_role not in VALID_ROLES:
        raise ValueError(f"Invalid API token role '{role}'. Allowed: {VALID_ROLES}")

    cleaned_name = name.strip()
    if not cleaned_name:
        raise ValueError("API token name cannot be empty.")
    if rate_limit is None or not 1 <= rate_limit <= 10000:
        raise ValueError("Rate limit must be between 1 and 10000 requests per minute.")
    if expires_in_days is not None and not 1 <= expires_in_days <= 3650:
        raise ValueError("Expiry must be between 1 and 3650 days, or null.")

    # Generate 48-char random hex string prefixed with cd_live_
    random_secret = secrets.token_hex(24)
    raw_token = f"{TOKEN_PREFIX}{random_secret}"
    token_prefix = f"{raw_token[:14]}…{raw_token[-4:]}"
    token_digest = hash_token(raw_token)

    expires_at_str = None
    if expires_in_days and expires_in_days > 0:
        expiry_dt = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
        expires_at_str = expiry_dt.strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO api_tokens (
                name, token_prefix, token_hash, role,
                created_by, expires_at, rate_limit_per_min, is_active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                cleaned_name,
                token_prefix,
                token_digest,
                cleaned_role,
                created_by,
                expires_at_str,
                rate_limit,
            ),
        )
        token_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT * FROM api_tokens WHERE id = ?", (token_id,))
        token_row = dict(cursor.fetchone())

    # Delete hash before returning metadata
    token_row.pop("token_hash", None)
    return raw_token, token_row


def verify_api_token(raw_token: str) -> dict | None:
    """
    Verify an API token from an incoming request header.
    Returns caller identity and role dictionary if valid, else None.
    """
    if not raw_token or not raw_token.startswith(TOKEN_PREFIX):
        return None

    digest = hash_token(raw_token)

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM api_tokens
            WHERE token_hash = ? AND is_active = 1
            """,
            (digest,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        token = dict(row)

        # Check expiration
        if token.get("expires_at"):
            try:
                # Parse expiry
                expiry_dt = datetime.strptime(token["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                now_utc = datetime.now(timezone.utc)
                if now_utc > expiry_dt:
                    return None
            except (TypeError, ValueError):
                return None

        # A database-backed fixed window is shared by all processes/workers.
        now = int(datetime.now(timezone.utc).timestamp())
        window = now - now % 60
        rate_limit = token["rate_limit_per_min"]
        if not isinstance(rate_limit, int) or rate_limit < 1:
            return None
        cursor.execute("""INSERT INTO api_rate_windows(token_id, window_start, request_count)
            VALUES (?, ?, 1) ON CONFLICT(token_id) DO UPDATE SET
            request_count = CASE WHEN window_start = excluded.window_start THEN request_count + 1 ELSE 1 END,
            window_start = excluded.window_start""", (token["id"], window))
        count = cursor.execute("SELECT request_count FROM api_rate_windows WHERE token_id = ?", (token["id"],)).fetchone()[0]
        if count > rate_limit:
            raise ApiRateLimitExceeded(window + 60 - now)

        # Update last_used_at asynchronously
        try:
            cursor.execute(
                "UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?",
                (token["id"],),
            )
            conn.commit()
        except Exception:
            pass

    return {
        "username": f"api:{token['name']}",
        "role": token["role"],
        "is_api_token": True,
        "token_id": token["id"],
        "token_name": token["name"],
        "rate_limit_per_min": token.get("rate_limit_per_min", 60),
        "rate_limit_remaining": max(0, rate_limit - count),
    }


def list_api_tokens() -> list[dict]:
    """Retrieve list of all registered API tokens (hashes excluded)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, name, token_prefix, role, created_by,
                   created_at, expires_at, last_used_at,
                   rate_limit_per_min, is_active
            FROM api_tokens
            ORDER BY id DESC
            """
        )
        rows = cursor.fetchall()

    return [dict(r) for r in rows]


def get_api_token_by_id(token_id: int) -> dict | None:
    """Get a single token metadata by ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, name, token_prefix, role, created_by,
                   created_at, expires_at, last_used_at,
                   rate_limit_per_min, is_active
            FROM api_tokens
            WHERE id = ?
            """,
            (token_id,),
        )
        row = cursor.fetchone()

    return dict(row) if row else None


def revoke_api_token(token_id: int) -> bool:
    """Revoke an active API token."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE api_tokens SET is_active = 0 WHERE id = ?",
            (token_id,),
        )
        conn.commit()
        return cursor.rowcount > 0


def delete_api_token(token_id: int) -> bool:
    """Permanently delete an API token record."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM api_tokens WHERE id = ?",
            (token_id,),
        )
        conn.commit()
        return cursor.rowcount > 0


def get_api_endpoints_catalog() -> list[dict]:
    """Build explorer metadata from actual routes and dependency permissions."""
    from app.main import app, require_admin, require_analyst_or_admin, require_authenticated_user
    schema = app.openapi()
    catalog = []
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api") or not hasattr(route, "dependant"):
            continue
        def dependency_calls(dependant):
            return {call for dependency in dependant.dependencies for call in ({dependency.call} | dependency_calls(dependency))}
        dependencies = dependency_calls(route.dependant)
        role = ("Admin" if require_admin in dependencies else "Analyst / Admin" if require_analyst_or_admin in dependencies
                else "Viewer (authenticated)" if require_authenticated_user in dependencies else "Public")
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            operation = schema.get("paths", {}).get(path, {}).get(method.lower(), {})
            endpoint_id = path.removeprefix("/api/").replace("-", "_") if method == "GET" else operation.get("operationId", path)
            catalog.append({"id": endpoint_id, "name": operation.get("summary", path), "method": method,
                            "path": path, "description": operation.get("description", ""), "auth_required": role,
                            "params": [{"name": p["name"], "type": p.get("schema", {}).get("type", "string"),
                                        "in": p["in"], "example": p.get("schema", {}).get("default", ""),
                                        "desc": p.get("description", "")} for p in operation.get("parameters", [])],
                            "has_body": "requestBody" in operation,
                            "sample_response": "// Execute a request to see actual results; no synthetic intelligence is shown."})
    return catalog
