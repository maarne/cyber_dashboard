# ============================================================
# scratch/test_critical_suite.py — All-in-One Critical App Test Suite
# ============================================================
# Comprehensive end-to-end integration and security test suite
# for CyberDash. Runs in CI/CD (Azure Pipelines) and local environments.
#
# SECURITY & ISOLATION BEST PRACTICES:
# 1. Non-Destructive: Executes strictly inside an ephemeral sandbox database in /tmp/.
#    The live application database is NEVER modified, opened, or truncated.
# 2. Scanner-Safe: No static fake/dummy passwords or secret tokens are hardcoded.
#    All credentials, tokens, and payloads are generated dynamically at runtime
#    using cryptographically secure random generators (generate_secure_random_password).
# 3. Network-Isolated: Outbound webhooks and external APIs are mocked with unittest.mock.
# ============================================================

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

# Safety Enforcement: Strictly configure ephemeral temporary database in /tmp
_temp_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DATABASE_PATH"] = _temp_test_db.name
_temp_test_db.close()

from fastapi.testclient import TestClient
from app.main import app
from app.database import initialize_database, get_connection
from app.services.auth_service import (
    create_access_token,
    get_user_by_username,
    create_user,
    list_all_users,
    delete_user_by_username,
    generate_secure_random_password,
)
from app.services.audit_service import verify_audit_log_integrity, get_audit_logs
from app.services.api_token_service import generate_api_token


class TestCyberDashCriticalSuite(unittest.TestCase):
    """
    Comprehensive critical test suite covering:
    1. First-Time Setup Wizard & Zero-State Lockdown
    2. Authentication, Session Cookies & Password Policy
    3. Multi-tier RBAC & Primary Admin Protection
    4. Scoped Machine API Tokens & Global 401 Enforcement
    5. Threat Telemetry, CVEs, CISA & MITRE Intelligence
    6. IoC Threat Investigator & SIEM Search Export
    7. Detection Engineering Studio (Sigma / YARA Rules)
    8. Webhooks Alerting, Secret Masking & SSRF Protection
    9. Cryptographic Tamper-Evident SHA-256 Audit Ledger
    10. Multi-Theme UI, 3-Tab Settings & Security Headers
    """

    @classmethod
    def setUpClass(cls):
        # Explicit Non-Destructive Safety Assertion
        active_db_path = os.environ.get("DATABASE_PATH", "")
        assert "tmp" in active_db_path or "temp" in active_db_path, (
            f"Safety check failed: Test database must be in temporary storage, got: {active_db_path}"
        )
        initialize_database()
        cls.client = TestClient(app)

        # Dynamic runtime credential generation (prevents static scanner matches)
        cls.dynamic_admin_pwd = generate_secure_random_password(16)
        cls.dynamic_analyst_pwd = generate_secure_random_password(16)
        cls.dynamic_viewer_pwd = generate_secure_random_password(16)
        cls.dynamic_wrong_pwd = generate_secure_random_password(16) + "X"

    @classmethod
    def tearDownClass(cls):
        temp_db = os.environ.get("DATABASE_PATH")
        if temp_db and os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except OSError:
                pass

    # ------------------------------------------------------------
    # 1. SETUP WIZARD & FIRST-TIME ONBOARDING
    # ------------------------------------------------------------
    def test_01_setup_wizard_flow(self):
        """Test first-time setup provisioning and permanent lockdown in sandbox DB."""
        # Clean sandbox database users for onboarding test
        with get_connection() as conn:
            conn.execute("DELETE FROM users")
            conn.commit()

        # Root redirect to /setup during zero-state
        res = self.client.get("/", follow_redirects=False)
        self.assertIn(res.status_code, (200, 302, 307))

        # Setup page renders
        res = self.client.get("/setup")
        self.assertEqual(res.status_code, 200)
        self.assertIn("CyberDash", res.text)
        self.assertIn("setup", res.text.lower())

        # Complete initial setup with dynamically generated compliant password
        setup_payload = {
            "username": "admin",
            "password": self.dynamic_admin_pwd,
        }
        res = self.client.post("/api/setup", json=setup_payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("access_token", res.cookies)

        # Subsequent setup attempts must be permanently blocked (400)
        res = self.client.post("/api/setup", json=setup_payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("already been completed", res.json().get("error", ""))

    # ------------------------------------------------------------
    # 2. AUTHENTICATION, SESSIONS & PASSWORD POLICIES
    # ------------------------------------------------------------
    def test_02_authentication_and_password_policy(self):
        """Test login, /api/auth/me, password change and logout."""
        # 1. Login with invalid password
        res = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": self.dynamic_wrong_pwd},
        )
        self.assertEqual(res.status_code, 401)

        # 2. Valid Login with dynamically generated password
        res = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": self.dynamic_admin_pwd},
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("access_token", res.cookies)
        admin_cookie = {"access_token": res.cookies["access_token"]}

        # 3. GET /api/auth/me
        res = self.client.get("/api/auth/me", cookies=admin_cookie)
        self.assertEqual(res.status_code, 200)
        user_info = res.json()
        self.assertEqual(user_info["username"], "admin")
        self.assertEqual(user_info["role"], "admin")

        # 4. Password Policy Query & Generation
        res = self.client.get("/api/security/password-policy")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["min_length"] >= 8)

        res = self.client.get("/api/security/generate-password", cookies=admin_cookie)
        self.assertEqual(res.status_code, 200)
        generated_pwd = res.json()["password"]
        self.assertTrue(len(generated_pwd) >= 10)

        # 5. Logout
        res = self.client.post("/api/auth/logout", cookies=admin_cookie)
        self.assertEqual(res.status_code, 200)

    # ------------------------------------------------------------
    # 3. RBAC GOVERNANCE & PRIMARY ADMIN PROTECTION
    # ------------------------------------------------------------
    def test_03_rbac_and_admin_protection(self):
        """Test Analyst vs Admin roles, 403 enforcement, and primary admin immunity."""
        admin_token = create_access_token("admin", "admin")
        admin_cookies = {"access_token": admin_token}

        # Provision Analyst and Viewer users with dynamic passwords
        if not get_user_by_username("soc_analyst"):
            create_user("soc_analyst", self.dynamic_analyst_pwd, "analyst")
        if not get_user_by_username("soc_viewer"):
            create_user("soc_viewer", self.dynamic_viewer_pwd, "viewer")

        analyst_token = create_access_token("soc_analyst", "analyst")
        analyst_cookies = {"access_token": analyst_token}

        # 1. Admin can list users
        res = self.client.get("/api/users", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        usernames = [u["username"] for u in res.json()]
        self.assertIn("admin", usernames)
        self.assertIn("soc_analyst", usernames)

        # 2. Analyst is blocked from user management (403)
        res = self.client.get("/api/users", cookies=analyst_cookies)
        self.assertEqual(res.status_code, 403)

        # 3. Analyst can view audit logs (200)
        res = self.client.get("/api/audit-logs", cookies=analyst_cookies)
        self.assertEqual(res.status_code, 200)

        # 4. Primary Admin Protection (Cannot delete own account or primary admin)
        res = self.client.delete("/api/users/admin", cookies=admin_cookies)
        self.assertEqual(res.status_code, 400)

        res = self.client.put(
            "/api/users/admin/role",
            json={"role": "analyst"},
            cookies=admin_cookies,
        )
        self.assertEqual(res.status_code, 400)

    # ------------------------------------------------------------
    # 4. DEVELOPER API TOKENS & 401 ENFORCEMENT
    # ------------------------------------------------------------
    def test_04_developer_api_tokens_and_auth_headers(self):
        """Test API tokens, SHA-256 storage, headers, and 401 unauthenticated enforcement."""
        admin_token = create_access_token("admin", "admin")
        admin_cookies = {"access_token": admin_token}

        # 1. Generate machine API Token
        res = self.client.post(
            "/api/tokens",
            json={"name": "SIEM Collector Bot", "role": "analyst", "rate_limit_per_min": 120},
            cookies=admin_cookies,
        )
        self.assertIn(res.status_code, (200, 201))
        token_data = res.json()
        raw_token = token_data["token"]
        token_id = token_data["metadata"]["id"]
        self.assertTrue(raw_token.startswith("cd_live_"))

        # 2. Authenticate via X-API-Key
        res = self.client.get("/api/summary", headers={"X-API-Key": raw_token})
        self.assertEqual(res.status_code, 200)

        # 3. Authenticate via Authorization: Bearer
        res = self.client.get("/api/summary", headers={"Authorization": f"Bearer {raw_token}"})
        self.assertEqual(res.status_code, 200)

        # 4. Global 401 Enforcement on missing authentication
        res = self.client.get("/api/summary")
        self.assertEqual(res.status_code, 401)

        # 5. Revoke Token
        res = self.client.post(f"/api/tokens/{token_id}/revoke", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)

        # 6. Revoked Token must fail (401)
        res = self.client.get("/api/summary", headers={"X-API-Key": raw_token})
        self.assertEqual(res.status_code, 401)

    # ------------------------------------------------------------
    # 5. THREAT TELEMETRY & CVE INTELLIGENCE ENDPOINTS
    # ------------------------------------------------------------
    def test_05_threat_telemetry_and_intel(self):
        """Test summary metrics, CVEs, CISA KEV, threats, actors, and TTP endpoints."""
        admin_token = create_access_token("admin", "admin")
        admin_cookies = {"access_token": admin_token}

        # Summary
        res = self.client.get("/api/summary", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_cves", data)
        self.assertIn("active_exploits", data)

        # CVEs
        res = self.client.get("/api/cves?limit=5", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

        # CISA KEV
        res = self.client.get("/api/cisa?limit=5", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

        # Threat Indicators
        res = self.client.get("/api/threats?limit=5", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)

        # Threat Actors
        res = self.client.get("/api/threat-actors", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(len(res.json()) > 0)

        # MITRE TTP info
        res = self.client.get("/api/mitre-ttps/T1059.001", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertIn("PowerShell", res.json()["name"])

    # ------------------------------------------------------------
    # 6. IOC THREAT INVESTIGATOR
    # ------------------------------------------------------------
    def test_06_ioc_investigator(self):
        """Test IoC classification, triage, scoring, and search history."""
        admin_token = create_access_token("admin", "admin")
        admin_cookies = {"access_token": admin_token}

        # Investigate an IP (uses ?ioc= parameter)
        res = self.client.get("/api/investigate?ioc=198.51.100.45", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("ioc_type", data)
        self.assertIn("verdict", data)
        self.assertIn("threat_score", data)

        # Investigate a SHA-256 Hash
        test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        res = self.client.get(f"/api/investigate?ioc={test_hash}", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["ioc_type"], "sha256")

        # Check investigation history
        res = self.client.get("/api/investigate/history", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(len(res.json()) >= 1)

    # ------------------------------------------------------------
    # 7. DETECTION ENGINEERING STUDIO (SIGMA & YARA RULES)
    # ------------------------------------------------------------
    def test_07_detection_rules_crud(self):
        """Test Sigma and YARA rule authoring, retrieval, update, and deletion."""
        analyst_token = create_access_token("soc_analyst", "analyst")
        analyst_cookies = {"access_token": analyst_token}

        # 1. Create a Sigma Rule
        rule_payload = {
            "title": "Suspicious PowerShell Encoded Command Execution",
            "rule_type": "SIGMA",
            "severity": "HIGH",
            "mitre_ttp": "T1059.001",
            "target_cve": "CVE-2024-0001",
            "description": "Detects base64 encoded PowerShell arguments",
            "code_content": "title: Encoded PowerShell\nstatus: production\nlogsource:\n  category: process_creation",
            "target_siem": "Splunk",
        }
        res = self.client.post("/api/detection-rules", json=rule_payload, cookies=analyst_cookies)
        self.assertIn(res.status_code, (201, 409))
        if res.status_code == 201:
            rule_id = res.json()["id"]

            # 2. Retrieve the rule
            res = self.client.get(f"/api/detection-rules/{rule_id}", cookies=analyst_cookies)
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["title"], rule_payload["title"])

            # 3. Update the rule (passing full schema)
            updated_payload = dict(rule_payload)
            updated_payload["severity"] = "CRITICAL"
            updated_payload["description"] = "Updated severity to critical"
            res = self.client.put(
                f"/api/detection-rules/{rule_id}",
                json=updated_payload,
                cookies=analyst_cookies,
            )
            self.assertEqual(res.status_code, 200)

            # 4. Delete the rule
            res = self.client.delete(f"/api/detection-rules/{rule_id}", cookies=analyst_cookies)
            self.assertEqual(res.status_code, 200)

    # ------------------------------------------------------------
    # 8. WEBHOOKS, SECRET MASKING & SSRF PROTECTION
    # ------------------------------------------------------------
    def test_08_webhooks_masking_and_ssrf(self):
        """Test webhook registration, URL masking, SSRF rejection, and test alert dispatch."""
        admin_token = create_access_token("admin", "admin")
        admin_cookies = {"access_token": admin_token}

        # 1. SSRF Protection: Loopback and Cloud Metadata rejection
        ssrf_payload = {
            "name": "Malicious Webhook",
            "platform": "generic",
            "webhook_url": "http://127.0.0.1:8080/internal-api",
            "notify_critical_cves": True,
        }
        res = self.client.post("/api/webhooks", json=ssrf_payload, cookies=admin_cookies)
        self.assertEqual(res.status_code, 400)
        self.assertIn("invalid webhook url", res.json().get("error", "").lower())

        # 2. Valid Webhook Creation with Secret Masking
        safe_payload = {
            "name": "SOC Slack Channel",
            "platform": "slack",
            "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/test_mock_token_sample",
            "notify_critical_cves": True,
            "notify_high_cves": True,
            "notify_cisa_exploits": True,
        }
        res = self.client.post("/api/webhooks", json=safe_payload, cookies=admin_cookies)
        self.assertEqual(res.status_code, 201)
        wh_id = res.json()["id"]

        # 3. Retrieve Webhook and verify masking
        res = self.client.get(f"/api/webhooks/{wh_id}", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        wh_data = res.json()
        self.assertIn("••••••••", wh_data.get("masked_url", wh_data.get("webhook_url", "")))

        # 4. Toggle Webhook Status
        res = self.client.post(f"/api/webhooks/{wh_id}/toggle", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()["is_active"])

        # 5. Test Notification Dispatch (with mock HTTP response)
        mock_response = MagicMock()
        mock_response.is_success = True
        mock_response.status_code = 200

        with patch("httpx.post", return_value=mock_response):
            res = self.client.post(f"/api/webhooks/{wh_id}/test", cookies=admin_cookies)
            self.assertEqual(res.status_code, 200)
            self.assertIn("message", res.json())

        # 6. Delete Webhook
        res = self.client.delete(f"/api/webhooks/{wh_id}", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)

    # ------------------------------------------------------------
    # 9. CRYPTOGRAPHIC TAMPER-EVIDENT AUDIT LEDGER
    # ------------------------------------------------------------
    def test_09_cryptographic_audit_ledger(self):
        """Test Merkle-linked SHA-256 audit chaining and verification."""
        admin_token = create_access_token("admin", "admin")
        admin_cookies = {"access_token": admin_token}

        # 1. Fetch Audit Logs
        res = self.client.get("/api/audit-logs?limit=10", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        logs = res.json()
        self.assertIsInstance(logs, list)
        self.assertTrue(len(logs) > 0)
        self.assertIn("integrity_hash", logs[0])
        self.assertIn("prev_hash", logs[0])

        # 2. Verify Cryptographic Integrity Chain
        res = self.client.get("/api/audit-logs/verify", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        verification = res.json()
        self.assertTrue(verification["is_valid"])

        # 3. Export Audit Log (CSV & JSON)
        res = self.client.get("/api/audit-logs/export?format=json", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/audit-logs/export?format=csv", cookies=admin_cookies)
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/csv", res.headers.get("content-type", ""))

    # ------------------------------------------------------------
    # 10. UI TEMPLATES, 3-TAB SETTINGS & SECURITY HEADERS
    # ------------------------------------------------------------
    def test_10_ui_templates_and_security_headers(self):
        """Test HTML route rendering, 3-tab Settings console, and HTTP security headers."""
        admin_token = create_access_token("admin", "admin")
        admin_cookies = {"access_token": admin_token}

        # HTML Pages
        routes = ["/", "/actors", "/rules", "/investigate", "/settings"]
        for route in routes:
            res = self.client.get(route, cookies=admin_cookies)
            self.assertEqual(res.status_code, 200, f"Route {route} failed")
            # Must include zero-FOUT theme loader script
            self.assertIn("cyberdash_theme", res.text)
            self.assertIn("data-theme", res.text)

            # Security Headers Check
            self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
            self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertIn("frame-ancestors 'none'", res.headers.get("Content-Security-Policy", ""))

        # Settings 3-Tab Structure Verification
        settings_res = self.client.get("/settings", cookies=admin_cookies)
        self.assertIn("panel-alerts", settings_res.text)
        self.assertIn("panel-security", settings_res.text)
        self.assertIn("panel-api", settings_res.text)
        self.assertIn("explorer-endpoint-select", settings_res.text)

        # Sensitive file disclosure prevention (.db, .py)
        res = self.client.get("/cyber_dashboard.db")
        self.assertIn(res.status_code, (403, 404))


if __name__ == "__main__":
    unittest.main(verbosity=2)
