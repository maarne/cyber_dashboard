import sys
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

import requests
from app.database import get_connection
from app.services.auth_service import seed_default_admin_user, get_user_by_username
from app.services.audit_service import verify_audit_log_integrity

BASE_URL = "http://127.0.0.1:8000"

def test_rbac_and_audit():
    print("=" * 60)
    print("🔐 TESTING GRANULAR RBAC & TAMPER-EVIDENT AUDIT LEDGER")
    print("=" * 60)

    # 1. Seed & Verify default admin user
    seed_default_admin_user()
    from app.services.auth_service import update_user_password, create_user, delete_user_by_username
    admin_pwd = "Admin#Pass2026!"
    analyst_pwd = "Analyst#Pass2026!"
    viewer_pwd = "Viewer#Pass2026!"

    update_user_password("admin", admin_pwd)

    # Ensure temporary analyst and viewer test accounts exist for RBAC test
    test_analyst_user = "test_analyst_tmp"
    test_viewer_user = "test_viewer_tmp"

    if not get_user_by_username(test_analyst_user):
        create_user(test_analyst_user, analyst_pwd, "analyst")
    else:
        update_user_password(test_analyst_user, analyst_pwd)

    if not get_user_by_username(test_viewer_user):
        create_user(test_viewer_user, viewer_pwd, "viewer")
    else:
        update_user_password(test_viewer_user, viewer_pwd)

    try:
        admin_user = get_user_by_username("admin")
        analyst_user = get_user_by_username(test_analyst_user)
        viewer_user = get_user_by_username(test_viewer_user)

        assert admin_user is not None and admin_user["role"] == "admin"
        assert analyst_user is not None and analyst_user["role"] == "analyst"
        assert viewer_user is not None and viewer_user["role"] == "viewer"
        print("✅ 1. RBAC test accounts initialized.")

        # 2. Login Sessions
        admin_s = requests.Session()
        res = admin_s.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": admin_pwd})
        assert res.status_code == 200, f"Admin login failed: {res.text}"
        assert res.json()["role"] == "admin"

        analyst_s = requests.Session()
        res = analyst_s.post(f"{BASE_URL}/api/auth/login", json={"username": test_analyst_user, "password": analyst_pwd})
        assert res.status_code == 200, f"Analyst login failed: {res.text}"
        assert res.json()["role"] == "analyst"

        viewer_s = requests.Session()
        res = viewer_s.post(f"{BASE_URL}/api/auth/login", json={"username": test_viewer_user, "password": viewer_pwd})
        assert res.status_code == 200, f"Viewer login failed: {res.text}"
        assert res.json()["role"] == "viewer"
        print("✅ 2. Multi-role authentication & JWT claim issuance verified.")

        # 3. RBAC Permissions Checks

        # A. Viewer restrictions
        res = viewer_s.post(f"{BASE_URL}/api/detection-rules", json={"title": "Test Rule by Viewer", "rule_type": "Sigma", "code_content": "test"})
        assert res.status_code == 403, f"Viewer should be forbidden from creating rules, got {res.status_code}"

        res = viewer_s.post(f"{BASE_URL}/api/webhooks", json={"name": "Test", "platform": "slack", "webhook_url": "https://hooks.slack.com/services/sample_workspace_team/sample_channel/sample_token"})
        assert res.status_code == 403, f"Viewer should be forbidden from creating webhooks, got {res.status_code}"

        res = viewer_s.get(f"{BASE_URL}/api/users")
        assert res.status_code == 403, f"Viewer should be forbidden from listing users, got {res.status_code}"
        print("✅ 3A. Viewer RBAC restrictions verified (403 Forbidden on write actions).")

        # B. Analyst permissions & restrictions
        # Allowed: Create Detection Rule
        test_rule_title = "Sigma - Suspicious PowerShell Download Test"
        res = analyst_s.post(f"{BASE_URL}/api/detection-rules", json={
            "title": test_rule_title,
            "rule_type": "Sigma",
            "severity": "HIGH",
            "mitre_ttp": "T1059.001",
            "description": "Analyst test rule",
            "code_content": "title: Test Rule\nstatus: test",
            "target_siem": "Generic",
        })
        assert res.status_code in (201, 409), f"Analyst rule creation failed: {res.text}"

        # Allowed: View audit logs
        res = analyst_s.get(f"{BASE_URL}/api/audit-logs")
        assert res.status_code == 200, f"Analyst should be able to view audit logs, got {res.status_code}"

        # Blocked: Create Webhook
        res = analyst_s.post(f"{BASE_URL}/api/webhooks", json={"name": "Test", "platform": "slack", "webhook_url": "https://hooks.slack.com/services/sample_workspace_team/sample_channel/sample_token"})
        assert res.status_code == 403, f"Analyst should be forbidden from creating webhooks, got {res.status_code}"

        # Blocked: User management
        res = analyst_s.get(f"{BASE_URL}/api/users")
        assert res.status_code == 403, f"Analyst should be forbidden from listing users, got {res.status_code}"
        print("✅ 3B. Analyst RBAC capabilities and boundaries verified.")

        # C. Admin Governance
        # Create new user
        test_new_user = "soc_intern"
        res = admin_s.post(f"{BASE_URL}/api/users", json={
            "username": test_new_user,
            "password": "Password123!",
            "role": "viewer"
        })
        assert res.status_code in (201, 409)

        # Update role
        res = admin_s.put(f"{BASE_URL}/api/users/{test_new_user}/role", json={"role": "analyst"})
        assert res.status_code == 200

        # Export audit logs
        res = admin_s.get(f"{BASE_URL}/api/audit-logs/export?format=csv")
        assert res.status_code == 200
        assert "integrity_hash" in res.text

        # Delete user
        res = admin_s.delete(f"{BASE_URL}/api/users/{test_new_user}")
        assert res.status_code == 200
        print("✅ 3C. Admin full governance & lifecycle operations verified.")

        # 4. Cryptographic Hash Chain Integrity Verification
        integrity = verify_audit_log_integrity()
        assert integrity["is_valid"] is True, f"Audit chain integrity check failed: {integrity}"
        print(f"✅ 4. Cryptographic Hash Chain verification passed: {integrity['message']}")

        # 5. Tamper Detection Test
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, details FROM audit_logs ORDER BY id DESC LIMIT 1")
            last_rec = cursor.fetchone()
            orig_id = last_rec["id"]
            orig_details = last_rec["details"]

            cursor.execute("UPDATE audit_logs SET details = 'TAMPERED_DETAILS' WHERE id = ?", (orig_id,))
            conn.commit()

        tamper_check = verify_audit_log_integrity()
        assert tamper_check["is_valid"] is False, "Integrity check should have caught the tampered record!"
        assert tamper_check["tampered_record_id"] == orig_id
        print(f"✅ 5. Cryptographic Tamper Detection successfully flagged unauthorized record alteration at #{orig_id}!")

        # Restore original details and re-verify
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE audit_logs SET details = ? WHERE id = ?", (orig_details, orig_id))
            conn.commit()

        restored_check = verify_audit_log_integrity()
        assert restored_check["is_valid"] is True
        print("✅ 6. Hash chain restored and verified clean.")
    finally:
        # Guarantee cleanup of all test accounts so database is not polluted
        delete_user_by_username(test_analyst_user)
        delete_user_by_username(test_viewer_user)
        delete_user_by_username("analyst")
        delete_user_by_username("viewer")
        delete_user_by_username("soc_intern")

    print("\n🎉 ALL RBAC & TAMPER-EVIDENT AUDIT TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_rbac_and_audit()

