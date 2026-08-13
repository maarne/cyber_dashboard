# ============================================================
# app/services/auth_service.py — Authentication, RBAC & Security Service
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# Handles password hashing (bcrypt), Role-Based Access Control (RBAC),
# JSON Web Token (JWT) claims generation and verification, and user
# account lifecycle management for CyberDash.
#
# WHY DO WE USE BCRYPT & JWT CLAIMS?
# ----------------------------------
# 1. bcrypt: Passwords should NEVER be stored in plaintext. bcrypt
#    uses an adaptive cryptographic hash algorithm with a unique
#    random salt per password and multiple rounds of computation.
#    This makes brute-force dictionary and rainbow table attacks infeasible.
# 2. JWT (JSON Web Token) with RBAC Claims: Stateless authentication tokens
#    signed with HMAC-SHA256 (HS256) that encode both the user's identity ('sub')
#    and their authorization tier ('role': Admin, Analyst, or Viewer).
#
# PYTHON CONCEPTS COVERED:
# - Cryptographic salting and hashing with the bcrypt library
# - JWT token encoding and decoding with pyjwt
# - Parameterized SQL statements with SQLite
# - Role-based authorization validation
# - Exception handling for malformed or expired tokens
# ============================================================

import string
import secrets
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

VALID_ROLES = {"admin", "analyst", "viewer"}


# ============================================================
# CRYPTOGRAPHIC RANDOM PASSWORD GENERATOR
# ============================================================

def generate_secure_random_password(length: int = 10) -> str:
    """
    Generate a cryptographically secure random password of specified length
    guaranteeing a balanced mix of uppercase, lowercase, numbers, and special characters.

    Characteristics:
        - Uppercase letters (A-Z)
        - Lowercase letters (a-z)
        - Numeric digits (0-9)
        - Special characters (!@#$%^&*()_+-=)
    """
    length = max(6, length)
    uppers = string.ascii_uppercase
    lowers = string.ascii_lowercase
    digits = string.digits
    specials = "!@#$%^&*()_+-="

    # Guarantee at least 1 of each character class
    chosen = [
        secrets.choice(uppers),
        secrets.choice(lowers),
        secrets.choice(digits),
        secrets.choice(specials),
    ]

    all_chars = uppers + lowers + digits + specials
    for _ in range(length - 4):
        chosen.append(secrets.choice(all_chars))

    # Securely shuffle character positions
    secrets.SystemRandom().shuffle(chosen)
    return "".join(chosen)


# ============================================================
# PASSWORD POLICY MANAGEMENT & VALIDATION
# ============================================================

def get_password_policy() -> dict:
    """
    Fetch active password security policy from SQLite.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT min_length, require_uppercase, require_lowercase, require_numbers, require_special, updated_at
                FROM security_policies
                ORDER BY id DESC LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                return {
                    "min_length": int(row["min_length"]),
                    "require_uppercase": bool(row["require_uppercase"]),
                    "require_lowercase": bool(row["require_lowercase"]),
                    "require_numbers": bool(row["require_numbers"]),
                    "require_special": bool(row["require_special"]),
                    "updated_at": row["updated_at"] or "",
                }
    except Exception:
        pass

    return {
        "min_length": 10,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special": True,
        "updated_at": "",
    }


def update_password_policy(
    min_length: int = 10,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_numbers: bool = True,
    require_special: bool = True,
) -> dict:
    """
    Update the minimum password policy in the database.
    """
    min_length = max(6, min(64, int(min_length)))
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE security_policies
            SET min_length = ?,
                require_uppercase = ?,
                require_lowercase = ?,
                require_numbers = ?,
                require_special = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = (SELECT id FROM security_policies ORDER BY id DESC LIMIT 1)
        """, (
            min_length,
            1 if require_uppercase else 0,
            1 if require_lowercase else 0,
            1 if require_numbers else 0,
            1 if require_special else 0,
        ))
        if cursor.rowcount == 0:
            cursor.execute("""
                INSERT INTO security_policies (min_length, require_uppercase, require_lowercase, require_numbers, require_special)
                VALUES (?, ?, ?, ?, ?)
            """, (
                min_length,
                1 if require_uppercase else 0,
                1 if require_lowercase else 0,
                1 if require_numbers else 0,
                1 if require_special else 0,
            ))
        conn.commit()
    return get_password_policy()


def validate_password_against_policy(password: str) -> tuple[bool, str]:
    """
    Validate candidate password string against active database security policy.
    Returns: (is_valid: bool, error_message: str)
    """
    if not password:
        return False, "Password cannot be empty."

    policy = get_password_policy()
    min_len = policy["min_length"]

    if len(password) < min_len:
        return False, f"Password must be at least {min_len} characters in length."

    if policy["require_uppercase"] and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter (A-Z)."

    if policy["require_lowercase"] and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter (a-z)."

    if policy["require_numbers"] and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one numeric digit (0-9)."

    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    if policy["require_special"] and not any(c in special_chars for c in password):
        return False, f"Password must contain at least one special character ({special_chars[:8]}...)."

    return True, ""


# ============================================================
# BCRYPT HASHING & JWT CLAIMS
# ============================================================

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


def create_access_token(username: str, role: str = "viewer") -> str:
    """
    Generate a signed JWT access token encoding the username and RBAC role.
    """
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": username,
        "role": role.lower() if role in VALID_ROLES else "viewer",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> dict | None:
    """
    Decode and validate a JWT access token.
    Returns: {"username": str, "role": str} if valid, None if expired or signature invalid.
    """
    try:
        payload = jwt.decode(
            token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM]
        )
        return {
            "username": payload.get("sub"),
            "role": payload.get("role", "viewer"),
        }
    except jwt.PyJWTError:
        return None


# ============================================================
# USER LIFECYCLE & DATABASE OPERATIONS
# ============================================================

def get_user_by_username(username: str) -> dict | None:
    """Retrieve user record by username."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, role, last_login, created_at, updated_at FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def list_all_users() -> list[dict]:
    """Retrieve all users without password hashes."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, role, last_login, created_at, updated_at FROM users ORDER BY id ASC"
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            u = dict(r)
            if not u.get("role"):
                u["role"] = "admin" if u["username"] == DEFAULT_ADMIN_USERNAME else "viewer"
            results.append(u)
        return results


def create_user(username: str, password: str, role: str = "viewer") -> dict:
    """Create a new user with a hashed password and assigned RBAC role."""
    clean_role = role.lower() if role.lower() in VALID_ROLES else "viewer"
    pwd_hash = hash_password(password)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, pwd_hash, clean_role),
        )
        conn.commit()
        user_id = cursor.lastrowid
    return {"id": user_id, "username": username, "role": clean_role}


def update_user_role(username: str, new_role: str) -> bool:
    """Update the RBAC role for a user."""
    clean_role = new_role.lower()
    if clean_role not in VALID_ROLES:
        return False
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
            (clean_role, username),
        )
        conn.commit()
        return cursor.rowcount > 0


def delete_user_by_username(username: str) -> bool:
    """Delete a user from the system. Prevents deleting the primary default admin account."""
    if username.lower() == DEFAULT_ADMIN_USERNAME.lower():
        return False

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return cursor.rowcount > 0


def update_user_password(username: str, new_password: str) -> bool:
    """Update password for an existing user."""
    pwd_hash = hash_password(new_password)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
            (pwd_hash, username),
        )
        conn.commit()
        return cursor.rowcount > 0


def record_user_login(username: str) -> None:
    """Record login timestamp for user accountability."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_login = datetime('now') WHERE username = ?",
                (username,),
            )
            conn.commit()
    except Exception:
        pass


def is_initial_setup_required() -> bool:
    """
    Check if the first-time initial administrator setup is required.
    Returns True if no admin account exists in the database.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
            row = cursor.fetchone()
            return (row["count"] == 0) if row else True
    except Exception:
        return True


def complete_initial_setup(username: str, password: str) -> dict:
    """
    Complete initial first-time setup by creating the primary administrator account.
    """
    if not is_initial_setup_required():
        raise ValueError("Initial setup has already been completed.")

    clean_username = username.strip() or "admin"
    is_valid, err_msg = validate_password_against_policy(password)
    if not is_valid:
        raise ValueError(err_msg)

    pwd_hash = hash_password(password)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (clean_username, pwd_hash),
        )
        conn.commit()
        user_id = cursor.lastrowid

    return {"id": user_id, "username": clean_username, "role": "admin"}


def seed_default_admin_user() -> None:
    """
    Check initial setup status. If setup is required, log a setup prompt message.
    """
    if is_initial_setup_required():
        print("=" * 60)
        print("🚀 FIRST-TIME SETUP REQUIRED:")
        print("   Navigate to http://127.0.0.1:8000/ to set your initial")
        print("   administrator credentials via the Setup Wizard.")
        print("=" * 60)

