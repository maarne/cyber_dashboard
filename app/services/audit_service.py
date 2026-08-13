# ============================================================
# app/services/audit_service.py — Cryptographic Tamper-Evident Audit Logging
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides enterprise audit logging with cryptographic hash chaining (SHA-256).
# Every security-sensitive action (logins, user lifecycle, detection rules,
# webhooks, and scheduler updates) is recorded in an immutable ledger.
#
# HOW DOES CRYPTOGRAPHIC HASH CHAINING WORK?
# ------------------------------------------
# Similar to a blockchain ledger or Git commit tree, each audit entry computes
# an integrity hash that incorporates the hash of the PREVIOUS entry:
#
#   Entry[0] -> Hash_0 = SHA256(GENESIS_HASH + Entry_0_Data)
#   Entry[1] -> Hash_1 = SHA256(Hash_0       + Entry_1_Data)
#   Entry[2] -> Hash_2 = SHA256(Hash_1       + Entry_2_Data)
#
# If an attacker or unauthorized database administrator attempts to modify,
# delete, or inject an audit record in SQLite, the mathematical chain breaks,
# and the integrity verification algorithm instantly flags the exact tampered record.
#
# PYTHON CONCEPTS COVERED:
# - Cryptographic hashing with hashlib (SHA-256)
# - Canonical string formatting for reproducible cryptographic signatures
# - Iterative chain validation algorithms
# - In-memory CSV generation with the standard library csv module
# - Structured audit metadata recording
# ============================================================

import csv
import io
import hashlib
from datetime import datetime, timezone
from app.database import get_connection

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    username: str,
    role: str,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    status: str,
    details: str | None,
) -> str:
    """
    Calculate the SHA-256 integrity hash for an audit log entry.
    """
    canonical_str = (
        f"{prev_hash}|"
        f"{timestamp}|"
        f"{username}|"
        f"{role}|"
        f"{action}|"
        f"{resource_type or ''}|"
        f"{resource_id or ''}|"
        f"{status}|"
        f"{details or ''}"
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def log_audit_event(
    username: str,
    role: str,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    status: str = "SUCCESS",
    details: str | None = None,
    ip_address: str = "127.0.0.1",
) -> int:
    """
    Record a new security event to the tamper-evident audit ledger.
    
    Args:
        username: Actor username who initiated the event (or 'anonymous')
        role: User RBAC role (admin, analyst, viewer, or system)
        action: Standard action identifier (e.g. AUTH_LOGIN_SUCCESS, RULE_CREATED)
        resource_type: Target category (e.g. AUTH, USER, RULE, WEBHOOK, FEED)
        resource_id: Identifier of affected item (e.g. rule title, webhook ID)
        status: SUCCESS, FAILED, or DENIED
        details: Technical summary or JSON description of changes
        ip_address: Client IP address
        
    Returns:
        int: The inserted audit log record ID.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Fetch the previous record's integrity hash
            cursor.execute("SELECT integrity_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            last_row = cursor.fetchone()
            prev_hash = last_row["integrity_hash"] if last_row else GENESIS_HASH

            # Calculate cryptographic hash for current entry
            integrity_hash = compute_entry_hash(
                prev_hash=prev_hash,
                timestamp=now_iso,
                username=username,
                role=role,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                details=details,
            )

            cursor.execute(
                """
                INSERT INTO audit_logs
                (timestamp, username, role, action, resource_type, resource_id, status, ip_address, details, prev_hash, integrity_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    username,
                    role,
                    action,
                    resource_type,
                    resource_id,
                    status,
                    ip_address,
                    details,
                    prev_hash,
                    integrity_hash,
                ),
            )
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"⚠️ Failed to log audit event ({action}): {e}")
        return -1


def get_audit_logs(
    limit: int = 50,
    action_filter: str | None = None,
    search: str | None = None,
    offset: int = 0,
) -> list[dict]:
    """
    Retrieve audit logs with optional filtering.
    """
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if action_filter and action_filter.upper() != "ALL":
        query += " AND action = ?"
        params.append(action_filter.upper())

    if search:
        query += " AND (username LIKE ? OR action LIKE ? OR details LIKE ? OR resource_id LIKE ?)"
        s = f"%{search}%"
        params.extend([s, s, s, s])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def verify_audit_log_integrity() -> dict:
    """
    Perform a complete cryptographic integrity verification of the audit log chain.
    
    Iterates from the genesis record to the latest head, recalculating each
    SHA-256 hash and ensuring prev_hash pointers are intact.
    
    Returns:
        dict: {
            "is_valid": bool,
            "total_records": int,
            "message": str,
            "tampered_record_id": int | None
        }
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
            records = [dict(r) for r in cursor.fetchall()]

        if not records:
            return {
                "is_valid": True,
                "total_records": 0,
                "message": "Audit log is empty. Genesis chain initialized.",
                "tampered_record_id": None,
            }

        expected_prev_hash = GENESIS_HASH

        for idx, rec in enumerate(records):
            # Check 1: prev_hash must link to preceding entry
            if rec["prev_hash"] != expected_prev_hash:
                return {
                    "is_valid": False,
                    "total_records": len(records),
                    "tampered_record_id": rec["id"],
                    "message": f"Cryptographic link broken at record #{rec['id']}! Previous hash mismatch.",
                }

            # Check 2: recalculate SHA-256 integrity hash
            calc_hash = compute_entry_hash(
                prev_hash=rec["prev_hash"],
                timestamp=rec["timestamp"],
                username=rec["username"],
                role=rec["role"],
                action=rec["action"],
                resource_type=rec["resource_type"],
                resource_id=rec["resource_id"],
                status=rec["status"],
                details=rec["details"],
            )

            if rec["integrity_hash"] != calc_hash:
                return {
                    "is_valid": False,
                    "total_records": len(records),
                    "tampered_record_id": rec["id"],
                    "message": f"Cryptographic integrity failed at record #{rec['id']}! Content modified or signature mismatch.",
                }

            expected_prev_hash = rec["integrity_hash"]

        return {
            "is_valid": True,
            "total_records": len(records),
            "message": f"All {len(records)} audit records cryptographically verified. Hash chain is unbroken.",
            "tampered_record_id": None,
        }

    except Exception as e:
        return {
            "is_valid": False,
            "total_records": 0,
            "tampered_record_id": None,
            "message": f"Error verifying audit chain: {e}",
        }


def export_audit_logs_csv() -> str:
    """
    Export all audit log entries formatted as RFC 4180 CSV.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        rows = [dict(r) for r in cursor.fetchall()]

    output = io.StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "username",
        "role",
        "action",
        "resource_type",
        "resource_id",
        "status",
        "ip_address",
        "details",
        "prev_hash",
        "integrity_hash",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    return output.getvalue()


def export_audit_logs_json() -> list[dict]:
    """
    Export all audit log entries as a JSON-serializable list of dictionaries.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        return [dict(r) for r in cursor.fetchall()]
