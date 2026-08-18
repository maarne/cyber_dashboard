import sys
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

import requests
import string
from app.services.auth_service import (
    generate_secure_random_password,
    get_password_policy,
    update_password_policy,
    validate_password_against_policy,
    seed_default_admin_user,
    list_all_users,
    update_user_password,
)

BASE_URL = "http://127.0.0.1:8000"

def test_password_policy_and_tabs():
    print("=" * 60)
    print("🔐 TESTING RANDOM PASSWORDS, POLICY ENGINE & TABBED SETTINGS")
    print("=" * 60)

    # 1. Test Random Password Generator
    pwd = generate_secure_random_password(10)
    assert len(pwd) == 10, f"Expected 10 chars, got {len(pwd)}"
    assert any(c.isupper() for c in pwd), "Missing uppercase"
    assert any(c.islower() for c in pwd), "Missing lowercase"
    assert any(c.isdigit() for c in pwd), "Missing digits"
    assert any(c in "!@#$%^&*()_+-=" for c in pwd), "Missing special characters"
    print(f"✅ 1. Random Password Generator verified (Sample: {pwd})")

    # 2. Test Single Default Admin Account
    seed_default_admin_user()
    # Reset admin password for deterministic test authentication
    admin_test_pwd = "Admin#Pass2026!"
    update_user_password("admin", admin_test_pwd)

    users = list_all_users()
    admin_exists = any(u["username"] == "admin" for u in users)
    assert admin_exists, "Admin account must exist"
    print(f"✅ 2. Default admin user verified. Total registered users: {len(users)}")

    # 3. Test Admin Authentication & Security Policy Endpoints
    admin_s = requests.Session()
    res = admin_s.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": admin_test_pwd})
    assert res.status_code == 200, f"Admin login failed: {res.text}"

    # Get active policy
    res = admin_s.get(f"{BASE_URL}/api/security/password-policy")
    assert res.status_code == 200
    policy = res.json()
    assert "min_length" in policy
    print(f"✅ 3A. GET /api/security/password-policy: {policy}")

    # Update policy (min_length=10, all required)
    res = admin_s.post(f"{BASE_URL}/api/security/password-policy", json={
        "min_length": 10,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special": True,
    })
    assert res.status_code == 200
    assert res.json()["policy"]["min_length"] == 10
    print("✅ 3B. POST /api/security/password-policy updated policy successfully.")

    # 4. Test Policy Enforcement on User Creation & Password Changes
    # Case A: Too short
    res = admin_s.post(f"{BASE_URL}/api/users", json={
        "username": "policy_test_user",
        "password": "Ab1!",
        "role": "analyst",
    })
    assert res.status_code == 400, "Should reject short password"
    assert "characters in length" in res.json()["error"]

    # Case B: Missing special character
    res = admin_s.post(f"{BASE_URL}/api/users", json={
        "username": "policy_test_user",
        "password": "Password1234",
        "role": "analyst",
    })
    assert res.status_code == 400, "Should reject missing special character"
    assert "special character" in res.json()["error"]

    # Case C: Fully compliant random password
    compliant_pwd = generate_secure_random_password(10)
    res = admin_s.post(f"{BASE_URL}/api/users", json={
        "username": "policy_test_user",
        "password": compliant_pwd,
        "role": "analyst",
    })
    assert res.status_code in (201, 409)
    print(f"✅ 4. Password Policy enforcement verified on user creation (Compliant: {compliant_pwd})")

    # Clean up test user
    admin_s.delete(f"{BASE_URL}/api/users/policy_test_user")

    # 5. Test 1-Click Generator Endpoint
    res = admin_s.get(f"{BASE_URL}/api/security/generate-password")
    assert res.status_code == 200
    gen_pwd = res.json()["password"]
    assert len(gen_pwd) == 10
    is_valid, _ = validate_password_against_policy(gen_pwd)
    assert is_valid is True
    print(f"✅ 5. GET /api/security/generate-password returned valid compliant password: {gen_pwd}")

    # 6. Test Settings Page HTML 3 Tabs Rendering
    res = admin_s.get(f"{BASE_URL}/settings")
    assert res.status_code == 200
    html = res.text
    assert 'id="panel-alerts"' in html
    assert 'id="panel-security"' in html
    assert 'id="panel-api"' in html
    assert 'switchSettingsTab' in html
    assert 'policy-min-length' in html
    assert 'policy-checklist' in html
    print("✅ 6. Settings Page 3-tab console and Security Policy UI rendering verified.")

    print("\n🎉 ALL RANDOM PASSWORD, POLICY ENGINE & TABBED SETTINGS TESTS PASSED!")

if __name__ == "__main__":
    test_password_policy_and_tabs()
