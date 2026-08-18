# ============================================================
# scratch/test_api_tokens.py — Comprehensive API Tokens & Developer Access Test Suite
# ============================================================

import os
import sys
import tempfile
import unittest

# Ensure workspace root is in sys.path
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

# Use isolated temporary test database so live database is NEVER modified
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
    delete_user_by_username,
)
from app.services.api_token_service import (
    generate_api_token,
    verify_api_token,
    list_api_tokens,
    get_api_token_by_id,
    revoke_api_token,
    delete_api_token,
    get_api_endpoints_catalog,
)
from app.services.audit_service import get_audit_logs, verify_audit_log_integrity


class TestApiTokensAndDeveloperAccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        cls.client = TestClient(app)

        # Ensure admin account exists in temporary test database
        if not get_user_by_username("admin"):
            create_user("admin", "TestAdmin1234!", "admin")

        # Setup test admin and analyst tokens for test client
        cls.admin_token = create_access_token("admin", "admin")
        cls.admin_headers = {"Cookie": f"access_token={cls.admin_token}"}

        # Create temporary viewer user
        if not get_user_by_username("test_viewer"):
            create_user("test_viewer", "TestViewer1234!", "viewer")
        cls.viewer_token = create_access_token("test_viewer", "viewer")
        cls.viewer_headers = {"Cookie": f"access_token={cls.viewer_token}"}

    @classmethod
    def tearDownClass(cls):
        delete_user_by_username("test_viewer")
        try:
            if os.path.exists(_temp_test_db.name):
                os.remove(_temp_test_db.name)
        except Exception:
            pass

    def test_01_token_generation_and_hashing(self):
        """Test generating scoped API tokens with SHA-256 hash preservation."""
        raw_token, meta = generate_api_token(
            name="Unit Test Splunk Ingestion",
            role="analyst",
            created_by="admin",
            expires_in_days=30,
            rate_limit=120,
        )

        self.assertTrue(raw_token.startswith("cd_live_"))
        self.assertNotIn("token_hash", meta)
        self.assertEqual(meta["name"], "Unit Test Splunk Ingestion")
        self.assertEqual(meta["role"], "analyst")
        self.assertEqual(meta["rate_limit_per_min"], 120)
        self.assertIsNotNone(meta["expires_at"])

        # Check in DB that token_hash is stored, not raw token
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM api_tokens WHERE id = ?", (meta["id"],))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertNotEqual(row["token_hash"], raw_token)
            self.assertEqual(len(row["token_hash"]), 64) # SHA-256 hex string

    def test_02_verify_api_token_auth(self):
        """Test verifying valid, invalid, and revoked tokens."""
        raw_token, meta = generate_api_token(
            name="Verify Test Bot",
            role="admin",
            created_by="admin",
        )

        # 1. Valid token verification
        auth_data = verify_api_token(raw_token)
        self.assertIsNotNone(auth_data)
        self.assertEqual(auth_data["role"], "admin")
        self.assertEqual(auth_data["token_id"], meta["id"])
        self.assertTrue(auth_data["is_api_token"])

        # 2. Invalid token string
        self.assertIsNone(verify_api_token("cd_live_invalid_token_12345"))
        self.assertIsNone(verify_api_token("not_a_valid_token"))

        # 3. Revoked token
        revoke_api_token(meta["id"])
        self.assertIsNone(verify_api_token(raw_token))

    def test_03_api_endpoints_dual_header_auth(self):
        """Test API request authentication using X-API-Key and Authorization: Bearer."""
        raw_token, meta = generate_api_token(
            name="Dual Header Test",
            role="analyst",
            created_by="admin",
        )

        # Test X-API-Key header
        res_key = self.client.get("/api/summary", headers={"X-API-Key": raw_token})
        self.assertEqual(res_key.status_code, 200)
        self.assertIn("total_cves", res_key.json())

        # Test Authorization: Bearer header
        res_bearer = self.client.get("/api/cves?limit=5", headers={"Authorization": f"Bearer {raw_token}"})
        self.assertEqual(res_bearer.status_code, 200)
        self.assertIsInstance(res_bearer.json(), list)

    def test_04_api_token_rbac_enforcement(self):
        """Test that viewer-scoped API token cannot access admin routes."""
        viewer_raw_token, meta = generate_api_token(
            name="Viewer Automation Key",
            role="viewer",
            created_by="admin",
        )

        # Viewer can access read-only intelligence
        res_read = self.client.get("/api/threats", headers={"X-API-Key": viewer_raw_token})
        self.assertEqual(res_read.status_code, 200)

        # Viewer CANNOT access admin token listing endpoint
        res_forbidden = self.client.get("/api/tokens", headers={"X-API-Key": viewer_raw_token})
        self.assertEqual(res_forbidden.status_code, 403)

    def test_05_api_token_lifecycle_rest_endpoints(self):
        """Test creating, listing, revoking, and deleting tokens via Admin REST API."""
        # 1. Create Token via POST /api/tokens
        payload = {
            "name": "REST API Integration Test",
            "role": "analyst",
            "expires_in_days": 90,
            "rate_limit_per_min": 100,
        }
        res_create = self.client.post("/api/tokens", json=payload, headers=self.admin_headers)
        self.assertEqual(res_create.status_code, 200)
        data = res_create.json()
        self.assertIn("token", data)
        self.assertTrue(data["token"].startswith("cd_live_"))
        created_id = data["metadata"]["id"]

        # 2. List Tokens via GET /api/tokens
        res_list = self.client.get("/api/tokens", headers=self.admin_headers)
        self.assertEqual(res_list.status_code, 200)
        token_names = [t["name"] for t in res_list.json()]
        self.assertIn("REST API Integration Test", token_names)

        # 3. Revoke Token via POST /api/tokens/{id}/revoke
        res_revoke = self.client.post(f"/api/tokens/{created_id}/revoke", headers=self.admin_headers)
        self.assertEqual(res_revoke.status_code, 200)

        # 4. Delete Token via DELETE /api/tokens/{id}
        res_delete = self.client.delete(f"/api/tokens/{created_id}", headers=self.admin_headers)
        self.assertEqual(res_delete.status_code, 200)

    def test_06_audit_trail_logging_for_api_tokens(self):
        """Verify token actions are logged into the SHA-256 tamper-evident ledger."""
        integrity = verify_audit_log_integrity()
        self.assertTrue(integrity["is_valid"])

        logs = get_audit_logs(limit=20)
        actions = [log["action"] for log in logs]
        self.assertIn("API_TOKEN_CREATED", actions)

    def test_07_endpoints_catalog_and_settings_page(self):
        """Verify endpoints catalog and settings HTML rendering."""
        catalog = get_api_endpoints_catalog()
        self.assertTrue(len(catalog) >= 5)
        endpoint_ids = [ep["id"] for ep in catalog]
        self.assertIn("summary", endpoint_ids)
        self.assertIn("cves", endpoint_ids)
        self.assertIn("investigate", endpoint_ids)

        # Check settings HTML page
        res = self.client.get("/settings", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        html = res.text
        self.assertIn("🔌 API &amp; Developer Access", html)
        self.assertIn("panel-api", html)
        self.assertIn("api-base-url-input", html)
        self.assertIn("explorer-endpoint-select", html)
        self.assertIn("create-token-modal", html)
        self.assertIn("reveal-token-modal", html)

    def test_08_api_root_and_docs_csp(self):
        """Verify /api directory, /redocs redirect, and CSP allowances on /docs and /redoc."""
        # 1. /api root directory - Unauthenticated must return 401
        res_unauth = self.client.get("/api")
        self.assertEqual(res_unauth.status_code, 401)

        # Authenticated must return 200
        res_api = self.client.get("/api", headers=self.admin_headers)
        self.assertEqual(res_api.status_code, 200)
        data = res_api.json()
        self.assertEqual(data["status"], "operational")
        self.assertIn("endpoints", data)
        self.assertIn("documentation", data)

        # 2. /redocs redirect
        res_redocs = self.client.get("/redocs", follow_redirects=False)
        self.assertEqual(res_redocs.status_code, 301)
        self.assertEqual(res_redocs.headers["location"], "/redoc")

        # 3. /docs CSP allows CDN
        res_docs = self.client.get("/docs")
        self.assertEqual(res_docs.status_code, 200)
        csp_docs = res_docs.headers.get("content-security-policy", "")
        self.assertIn("https://cdn.jsdelivr.net", csp_docs)

        # 4. /redoc CSP allows CDN & Google fonts
        res_redoc = self.client.get("/redoc")
        self.assertEqual(res_redoc.status_code, 200)
        csp_redoc = res_redoc.headers.get("content-security-policy", "")
        self.assertIn("https://cdn.jsdelivr.net", csp_redoc)
        self.assertIn("https://fonts.googleapis.com", csp_redoc)

    def test_09_webhook_authentication_and_url_masking(self):
        """Verify that /api/webhooks requires authentication and always masks secret tokens."""
        # 1. Unauthenticated request must return 401
        res_unauth = self.client.get("/api/webhooks")
        self.assertEqual(res_unauth.status_code, 401)

        # 2. Authenticated request returns webhooks with masked URLs
        res_auth = self.client.get("/api/webhooks", headers=self.admin_headers)
        self.assertEqual(res_auth.status_code, 200)
        webhooks = res_auth.json()
        for wb in webhooks:
            self.assertIn("••••", wb["webhook_url"])
            self.assertIn("••••", wb["masked_url"])


if __name__ == "__main__":
    unittest.main()
