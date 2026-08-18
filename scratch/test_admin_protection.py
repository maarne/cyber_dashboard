import sys
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

import requests
from app.database import get_connection
from app.services.auth_service import (
    create_user,
    update_user_password,
    get_user_by_username,
    update_user_role,
    delete_user_by_username,
)

BASE_URL = "http://127.0.0.1:8000"

def test_admin_protection():
    print("=" * 60)
    print("🛡️ TESTING ADMIN ACCOUNT IMMUNITY & GOVERNANCE SAFEGUARDS")
    print("=" * 60)

    # 1. Ensure admin account exists with known password
    admin_pwd = "Admin#Pass2026!"
    if not get_user_by_username("admin"):
        create_user("admin", admin_pwd, "admin")
    else:
        update_user_password("admin", admin_pwd)

    # Login as admin
    admin_s = requests.Session()
    res = admin_s.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": admin_pwd})
    assert res.status_code == 200, f"Login failed: {res.text}"

    # 2. Test Attempting to Demote 'admin' to Analyst -> MUST FAIL
    res = admin_s.put(f"{BASE_URL}/api/users/admin/role", json={"role": "analyst"})
    assert res.status_code == 400, f"Expected 400 rejection, got {res.status_code}"
    assert "cannot be demoted" in res.json()["error"].lower()
    print("✅ 1. Attempt to demote 'admin' to Analyst was rejected with 400 Bad Request.")

    # 3. Test Attempting to Demote 'admin' to Viewer -> MUST FAIL
    res = admin_s.put(f"{BASE_URL}/api/users/admin/role", json={"role": "viewer"})
    assert res.status_code == 400
    assert "cannot be demoted" in res.json()["error"].lower()
    print("✅ 2. Attempt to demote 'admin' to Viewer was rejected with 400 Bad Request.")

    # 4. Verify 'admin' role remains 'admin' in database
    admin_user = get_user_by_username("admin")
    assert admin_user["role"] == "admin"
    print("✅ 3. Database verified: 'admin' account role remains strictly 'admin'.")

    # 5. Test Secondary Admin Creation and Demotion
    # Create secondary admin
    sec_pwd = "SecAdmin#Pass2026!"
    if not get_user_by_username("secondary_admin"):
        create_user("secondary_admin", sec_pwd, "admin")
    else:
        update_user_role("secondary_admin", "admin")

    # Demoting secondary_admin when 'admin' exists -> Should SUCCEED
    res = admin_s.put(f"{BASE_URL}/api/users/secondary_admin/role", json={"role": "analyst"})
    assert res.status_code == 200, f"Failed to demote secondary admin: {res.text}"
    assert get_user_by_username("secondary_admin")["role"] == "analyst"
    print("✅ 4. Secondary admin role management works normally when another admin exists.")

    # Clean up secondary_admin
    admin_s.delete(f"{BASE_URL}/api/users/secondary_admin")

    # 6. Verify Settings HTML renders locked badge for 'admin'
    res = admin_s.get(f"{BASE_URL}/settings?tab=users")
    assert res.status_code == 200
    assert "Primary Administrator role is locked" in res.text
    assert "👑 Admin <span" in res.text
    print("✅ 5. Settings HTML verified: 'admin' is rendered with locked status, preventing dropdown editing.")

    print("\n🎉 ALL ADMIN PROTECTION & GOVERNANCE SAFEGUARD TESTS PASSED!")

if __name__ == "__main__":
    test_admin_protection()
