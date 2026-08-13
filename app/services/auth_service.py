# ============================================================
# app/services/auth_service.py — Authentication & Security Service
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Handles password hashing (bcrypt), JWT token generation/validation,
# and database user lookups for CyberDash authentication.
# ============================================================

from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from app.config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_HOURS,
    DEFAULT_ADMIN_USERNAME,
    DEFAULT_ADMIN_PASSWORD,
)
from app.database import get_connection


def hash_password(password: str) -> str:
    """
    Hash a password securely using bcrypt with a unique salt.
    """
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    """
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(username: str) -> str:
    """
    Generate a signed JWT access token for an authenticated user.
    """
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": username,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> str | None:
    """
    Decode and validate a JWT access token. Returns username if valid, None if invalid.
    """
    try:
        payload = jwt.decode(
            token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM]
        )
        return payload.get("sub")
    except (jwt.PyJWTError, ValueError):
        return None


# ============================================================
# DATABASE USER MANAGEMENT
# ============================================================

def get_user_by_username(username: str) -> dict | None:
    """
    Fetch a user record by username.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def create_user(username: str, password: str) -> dict:
    """
    Create a new user with a hashed password.
    """
    pwd_hash = hash_password(password)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pwd_hash),
        )
        conn.commit()
        user_id = cursor.lastrowid
    return {"id": user_id, "username": username}


def update_user_password(username: str, new_password: str) -> bool:
    """
    Update password for an existing user.
    """
    pwd_hash = hash_password(new_password)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
            (pwd_hash, username),
        )
        conn.commit()
        return cursor.rowcount > 0


def seed_default_admin_user() -> None:
    """
    Check if any user exists in the database. If not, seed the default admin account.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users")
        count = cursor.fetchone()["count"]
        if count == 0:
            pwd_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (DEFAULT_ADMIN_USERNAME, pwd_hash),
            )
            conn.commit()
            print(f"🔑 Initialized default admin user: '{DEFAULT_ADMIN_USERNAME}'")
