# ============================================================
# app/services/audit_service.py — Cryptographic Tamper-Evident Audit Logging
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Provides enterprise audit logging with cryptographic hash chaining (SHA-256).
# Every security-sensitive action (logins, user lifecycle, detection rules,
# webhooks, and scheduler updates) is recorded in a versioned hash chain.
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
# change an interior audit record, the chain breaks. Detecting full rewrites or
# tail deletion additionally requires a checkpoint stored outside this database.
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
import json
from contextlib import nullcontext
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
    ip_address: str | None = None,
    hash_version: int = 1,
) -> str:
    """
    Calculate the SHA-256 integrity hash for an audit log entry.
    """
    if hash_version == 2:
        canonical_str = json.dumps({
            "version": 2, "prev_hash": prev_hash, "timestamp": timestamp,
            "username": username, "role": role, "action": action,
            "resource_type": resource_type, "resource_id": resource_id,
            "status": status, "details": details, "ip_address": ip_address,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    if hash_version != 1:
        raise ValueError("Unsupported audit hash version.")
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
    connection=None,
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
        with (get_connection() if connection is None else nullcontext(connection)) as conn:
            # Lock before reading the head, not merely before INSERT.
            if connection is None:
                conn.execute("BEGIN IMMEDIATE")
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
                ip_address=ip_address,
                hash_version=2,
            )

            cursor.execute(
                """
                INSERT INTO audit_logs
                (timestamp, username, role, action, resource_type, resource_id, status, ip_address, details, prev_hash, integrity_hash, hash_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
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
            if connection is None:
                conn.commit()
            return cursor.lastrowid
    except Exception as e:
        if connection is not None:
            # The caller owns rollback: never commit a domain mutation without its audit event.
            raise
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


def verify_audit_log_integrity(checkpoint: dict | None = None) -> dict:
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

        if checkpoint:
            anchor = next((r for r in records if r["id"] == checkpoint["id"]), None)
            if not anchor or anchor["integrity_hash"] != checkpoint["integrity_hash"]:
                return {"is_valid": False, "total_records": len(records),
                        "tampered_record_id": checkpoint["id"], "message": "External checkpoint mismatch or ledger truncation detected."}
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
                ip_address=rec["ip_address"],
                hash_version=rec["hash_version"],
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
            "legacy_records": sum(r["hash_version"] == 1 for r in records),
            "checkpoint": {"id": records[-1]["id"], "integrity_hash": records[-1]["integrity_hash"]},
            "checkpoint_verified": checkpoint is not None,
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
        "hash_version",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: ("'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value)
                         for key, value in row.items()})

    return output.getvalue()


def export_audit_logs_json() -> list[dict]:
    """
    Export all audit log entries as a JSON-serializable list of dictionaries.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        return [dict(r) for r in cursor.fetchall()]
