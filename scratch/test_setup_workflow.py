import sys
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

import requests
from app.database import get_connection
from app.services.auth_service import (
    is_initial_setup_required,
    complete_initial_setup,
    get_user_by_username,
    generate_secure_random_password,
)
from app.services.audit_service import get_audit_logs, verify_audit_log_integrity

BASE_URL = "http://127.0.0.1:8000"

def test_setup_workflow():
    print("=" * 60)
    print("🚀 TESTING FIRST-TIME SETUP WIZARD & ONBOARDING WORKFLOW")
    print("=" * 60)

    # 1. Reset Admin Account to simulate clean zero-state setup mode
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE role = 'admin'")
        conn.commit()

    assert is_initial_setup_required() is True, "Setup must be required when no admin exists"
    print("✅ 1. Zero-state initialized. is_initial_setup_required() returned True.")

    # 2. Verify Route Redirection to /setup
    s = requests.Session()
    # Test GET / redirects to /setup
    res = s.get(f"{BASE_URL}/", allow_redirects=False)
    assert res.status_code == 307, f"Expected 307 redirect, got {res.status_code}"
    assert res.headers.get("location") == "/setup", f"Expected location /setup, got {res.headers.get('location')}"

    # Test GET /rules redirects to /setup
    res = s.get(f"{BASE_URL}/rules", allow_redirects=False)
    assert res.status_code == 307
    assert res.headers.get("location") == "/setup"

    # Test GET /settings redirects to /setup
    res = s.get(f"{BASE_URL}/settings", allow_redirects=False)
    assert res.status_code == 307
    assert res.headers.get("location") == "/setup"

    # Test GET /setup renders HTML wizard
    res = s.get(f"{BASE_URL}/setup")
    assert res.status_code == 200
    assert "Welcome to CyberDash" in res.text
    assert "setup-form" in res.text
    assert "setup-checklist" in res.text
    print("✅ 2. Automatic route redirection to /setup verified across multiple endpoints.")

    # 3. Test Policy Validation on POST /api/setup
    # Weak password test
    res = s.post(f"{BASE_URL}/api/setup", json={"username": "admin", "password": "weak"})
    assert res.status_code == 400
    assert "characters in length" in res.json()["error"]

    # Missing special character test
    res = s.post(f"{BASE_URL}/api/setup", json={"username": "admin", "password": "AlphaNumericOnly99"})
    assert res.status_code == 400
    assert "special character" in res.json()["error"]
    print("✅ 3. Password complexity policy enforcement verified on /api/setup.")

    # 4. Complete Setup with Strong Compliant Password
    admin_init_pwd = generate_secure_random_password(10)
    res = s.post(f"{BASE_URL}/api/setup", json={"username": "admin", "password": admin_init_pwd})
    assert res.status_code == 201, f"Setup failed: {res.text}"
    body = res.json()
    assert body["status"] == "success"
    assert body["redirect"] == "/"
    assert "access_token" in s.cookies
    print(f"✅ 4. POST /api/setup successfully completed setup (Password: {admin_init_pwd}). JWT cookie issued.")

    # 5. Verify Audit Log Recorded INITIAL_SETUP_COMPLETED
    logs = get_audit_logs(limit=5)
    setup_event = next((log for log in logs if log["action"] == "INITIAL_SETUP_COMPLETED"), None)
    assert setup_event is not None, "INITIAL_SETUP_COMPLETED event must be in audit ledger"
    assert setup_event["username"] == "admin"
    assert setup_event["role"] == "admin"

    # Cryptographic integrity check
    integrity = verify_audit_log_integrity()
    assert integrity["is_valid"] is True
    print("✅ 5. INITIAL_SETUP_COMPLETED event recorded in cryptographic audit ledger and verified.")

    # 6. Verify Post-Setup Behavior (Dashboard unlocked, Setup locked)
    assert is_initial_setup_required() is False

    # GET / renders dashboard
    res = s.get(f"{BASE_URL}/")
    assert res.status_code == 200
    assert "CyberDash" in res.text

    # GET /setup now redirects to /
    res = s.get(f"{BASE_URL}/setup", allow_redirects=False)
    assert res.status_code == 307
    assert res.headers.get("location") == "/"

    # POST /api/setup is permanently locked
    res = s.post(f"{BASE_URL}/api/setup", json={"username": "admin", "password": "NewPass#2026!"})
    assert res.status_code == 400
    assert "already been completed" in res.json()["error"]
    print("✅ 6. Lockdown verified: Dashboard unlocked, /setup and /api/setup secured against re-execution.")

    print("\n🎉 ALL FIRST-TIME SETUP WIZARD & ONBOARDING WORKFLOW TESTS PASSED!")

if __name__ == "__main__":
    test_setup_workflow()
