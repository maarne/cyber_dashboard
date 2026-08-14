#!/usr/bin/env python3
"""
=============================================================
CyberDash — Administrator Setup Reset Script
=============================================================
This script clears the administrator account credentials from
the SQLite database and places the application back into
First-Time Setup mode.

Usage:
    python reset_admin_setup.py
    # or
    ./reset_admin_setup.py
=============================================================
"""

import sys
import os
from pathlib import Path

# Ensure application directory is in Python path
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

try:
    from app.database import get_connection, initialize_database
    from app.services.auth_service import is_initial_setup_required
except ImportError as e:
    print(f"❌ Error: Unable to import CyberDash modules: {e}")
    sys.exit(1)


def reset_admin_setup():
    print("=" * 60)
    print("🛡️  CyberDash — Reset Admin Account & Force Setup Wizard")
    print("=" * 60)

    # Initialize database tables if needed
    initialize_database()

    # Clear admin account from database
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = 'admin' OR role = 'admin'")
        deleted_count = cursor.rowcount
        conn.commit()

    # Check setup status
    setup_needed = is_initial_setup_required()

    if setup_needed:
        print(f"✅ Successfully cleared {deleted_count} administrator account(s).")
        print("🚀 First-Time Setup mode is now ACTIVE.")
        print()
        print("👉 Navigate to http://127.0.0.1:8000/ in your browser.")
        print("   You will be automatically directed to the /setup onboarding page.")
        print("=" * 60)
    else:
        print("⚠️ Warning: Setup mode could not be activated (another admin may exist).")
        print("=" * 60)


if __name__ == "__main__":
    reset_admin_setup()
