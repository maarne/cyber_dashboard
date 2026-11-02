"""Small shared case primitives; audit and domain mutations share a transaction."""
from datetime import datetime, timezone
from contextlib import contextmanager
import sqlite3
from fastapi import HTTPException
from app.database import get_connection
from app.services.asset_service import canonical, check_version, literal_like, actor_key
from app.services.audit_service import log_audit_event


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


@contextmanager
def write_transaction():
    try:
        with get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            yield conn
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, 'A duplicate identifier or linked case/evidence constraint prevents this change.') from exc


def actor_values(actor):
    return actor.get('user_id'), actor.get('token_id'), actor['username']


def audit(conn, actor, action, object_id, details=None):
    return log_audit_event(actor['username'], actor['role'], action, resource_type='CASE', resource_id=str(object_id),
                           details=canonical({'actor_user_id': actor.get('user_id'), 'actor_token_id': actor.get('token_id'), **(details or {})}),
                           ip_address=actor.get('ip_address', 'unknown'), connection=conn)
