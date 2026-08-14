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
                rate_limit or 60,
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
            except Exception:
                pass

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
    """
    Structured directory of CyberDash API endpoints for the interactive explorer.
    """
    return [
        {
            "id": "summary",
            "name": "Dashboard Summary Metrics",
            "method": "GET",
            "path": "/api/summary",
            "description": "Real-time vulnerability counts, active CISA zero-days, RSS articles, and threat indicators.",
            "auth_required": "Viewer / Optional",
            "params": [
                {"name": "start_date", "type": "string", "example": "2026-01-01", "desc": "Filter by start date (YYYY-MM-DD)"},
                {"name": "end_date", "type": "string", "example": "2026-08-14", "desc": "Filter by end date (YYYY-MM-DD)"},
            ],
            "sample_response": '{\n  "total_cves": 142,\n  "critical_cves": 28,\n  "high_cves": 54,\n  "active_exploits": 19,\n  "total_articles": 85,\n  "total_threats": 42\n}',
        },
        {
            "id": "cves",
            "name": "Vulnerability Intelligence Feed",
            "method": "GET",
            "path": "/api/cves",
            "description": "Paginated CVE disclosures with EPSS scores, CVSS v3.1 vectors, Ransomware Campaign tags, and CISA flags.",
            "auth_required": "Viewer / Optional",
            "params": [
                {"name": "limit", "type": "integer", "example": "25", "desc": "Max records to return (1-200)"},
                {"name": "severity", "type": "string", "example": "CRITICAL", "desc": "CRITICAL, HIGH, MEDIUM, LOW"},
                {"name": "search", "type": "string", "example": "Fortinet", "desc": "Keyword or CVE ID search"},
            ],
            "sample_response": '[\n  {\n    "cve_id": "CVE-2026-1135",\n    "severity": "CRITICAL",\n    "cvss_score": 9.8,\n    "epss_score": 0.942,\n    "is_cisa_kev": true,\n    "ransomware_campaign": "LockBit 3.0"\n  }\n]',
        },
        {
            "id": "cisa",
            "name": "CISA Known Exploited Vulnerabilities",
            "method": "GET",
            "path": "/api/cisa",
            "description": "Curated catalog of actively exploited vulnerabilities compiled by the Cybersecurity & Infrastructure Security Agency.",
            "auth_required": "Viewer / Optional",
            "params": [
                {"name": "limit", "type": "integer", "example": "50", "desc": "Max records to return"},
            ],
            "sample_response": '[\n  {\n    "cve_id": "CVE-2026-2291",\n    "vendor_project": "Microsoft",\n    "product": "Windows Kernel",\n    "date_added": "2026-08-10"\n  }\n]',
        },
        {
            "id": "threats",
            "name": "Threat Actor Indicators & IoCs",
            "method": "GET",
            "path": "/api/threats",
            "description": "Active malicious IPs, domains, and hashes tracked across global telemetry sources.",
            "auth_required": "Viewer / Optional",
            "params": [
                {"name": "limit", "type": "integer", "example": "50", "desc": "Max records to return"},
                {"name": "type", "type": "string", "example": "ip", "desc": "ip, url, domain, hash"},
            ],
            "sample_response": '[\n  {\n    "indicator_type": "ip",\n    "indicator_value": "198.51.100.44",\n    "threat_type": "Command and Control",\n    "source": "Abuse.ch"\n  }\n]',
        },
        {
            "id": "investigate",
            "name": "IOC Threat Investigation & Enrichment",
            "method": "POST",
            "path": "/api/investigate",
            "description": "Correlates submitted IP addresses, domains, and file hashes against threat intelligence databases and Mitre ATT&CK.",
            "auth_required": "Viewer / Analyst",
            "params": [
                {"name": "ioc", "type": "string (JSON body)", "example": '{"ioc": "198.51.100.44"}', "desc": "Target indicator string"},
            ],
            "sample_response": '{\n  "ioc": "198.51.100.44",\n  "type": "ipv4",\n  "verdict": "MALICIOUS",\n  "threat_score": 92,\n  "associated_actors": ["APT29", "Cozy Bear"],\n  "matched_rules": ["Sigma-C2-Beaconing"]\n}',
        },
        {
            "id": "rules",
            "name": "Detection Rules Repository",
            "method": "GET",
            "path": "/api/rules",
            "description": "Enterprise Sigma and YARA rules mapped to MITRE ATT&CK techniques with SIEM deployment guidelines.",
            "auth_required": "Viewer / Analyst",
            "params": [
                {"name": "rule_type", "type": "string", "example": "SIGMA", "desc": "SIGMA or YARA"},
                {"name": "severity", "type": "string", "example": "CRITICAL", "desc": "CRITICAL, HIGH, MEDIUM"},
            ],
            "sample_response": '[\n  {\n    "id": 1,\n    "title": "PsExec Lateral Movement Detection",\n    "rule_type": "SIGMA",\n    "severity": "HIGH",\n    "mitre_id": "T1021.002"\n  }\n]',
        },
        {
            "id": "audit_logs",
            "name": "Cryptographic Audit Ledger",
            "method": "GET",
            "path": "/api/audit-logs",
            "description": "Cryptographically chained audit trail verifying governance integrity, authentication events, and administrative changes.",
            "auth_required": "Analyst / Admin",
            "params": [
                {"name": "action", "type": "string", "example": "USER_ROLE_UPDATED", "desc": "Action filter"},
                {"name": "search", "type": "string", "example": "admin", "desc": "Search keyword"},
            ],
            "sample_response": '[\n  {\n    "id": 114,\n    "username": "admin",\n    "role": "admin",\n    "action": "API_TOKEN_CREATED",\n    "status": "SUCCESS",\n    "integrity_hash": "a8f3b29..."\n  }\n]',
        },
    ]
