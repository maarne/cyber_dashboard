"""Regression coverage for the security/reliability issues found in review."""

from scratch import test_support

import os
import re
import socket
import sqlite3
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from unittest.mock import MagicMock, patch

import httpx
import jwt
from fastapi.testclient import TestClient
from app.database import initialize_database, get_connection
from app.main import app
from app.services import auth_service as auth, audit_service as audit
from app.services.api_token_service import generate_api_token, get_api_endpoints_catalog
from app.services.cve_intel_service import get_cve_details
from app.services.cve_service import fetch_and_store_cves, fetch_epss_scores
from app.services.cisa_service import fetch_and_store_cisa_kev
from app.services.ioc_service import investigate_ioc
from app.services.outbound_service import PublicNetworkBackend, is_safe_external_url, safe_request
from app.services.refresh_service import refresh_lease, run_feed_refresh
from app.services.rule_service import save_detection_rule
from app.services.webhook_service import mask_webhook_url, save_webhook, send_test_notification
from scripts.backup_database import backup_database


class ReviewRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        cls.password = auth.generate_secure_random_password(16)

    def setUp(self):
        test_support.assert_test_database()
        with get_connection() as conn:
            for table in ("api_rate_windows", "api_tokens", "users", "revoked_sessions", "audit_logs", "cves", "cisa_exploits", "threat_indicators", "investigation_history", "app_settings", "job_leases", "fetch_log"):
                conn.execute(f"DELETE FROM {table}")
            conn.execute('UPDATE installation_metadata SET admin_setup_completed=0 WHERE id=1')
            conn.execute("UPDATE security_policies SET min_length=10")
        auth.complete_initial_setup("primary_owner", self.password)
        self.client = TestClient(app, raise_server_exceptions=False)
        self.headers = {"Authorization": "Bearer " + auth.create_access_token("primary_owner")}

    def tearDown(self):
        self.client.close()

    def test_configuration_rejects_missing_and_known_secret(self):
        for secret in ("", "cyberdash-secret-key-change-in-production-2026"):
            result = subprocess.run([sys.executable, "-B", "-c", "import app.config"],
                                    env={**os.environ, "JWT_SECRET_KEY": secret}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Set JWT_SECRET_KEY", result.stderr)

    def test_forged_default_key_and_nonexistent_user_are_rejected(self):
        forged = jwt.encode({"sub": "missing", "role": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                            "cyberdash-secret-key-change-in-production-2026", algorithm="HS256")
        self.assertEqual(self.client.get("/api/users", headers={"Authorization": "Bearer " + forged}).status_code, 401)
        with self.assertRaises(ValueError):
            auth.create_access_token("missing", "admin")

    def test_role_change_and_deletion_invalidate_sessions(self):
        auth.create_user("secondary", self.password, "admin")
        headers = {"Authorization": "Bearer " + auth.create_access_token("secondary")}
        self.assertTrue(auth.update_user_role("secondary", "viewer")[0])
        self.assertEqual(self.client.get("/api/users", headers=headers).status_code, 401)
        headers = {"Authorization": "Bearer " + auth.create_access_token("secondary")}
        self.assertTrue(auth.delete_user_by_username("secondary"))
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 401)

    def test_logout_and_password_change_revoke_old_sessions(self):
        self.assertEqual(self.client.post("/api/auth/logout", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/users", headers=self.headers).status_code, 401)
        headers = {"Authorization": "Bearer " + auth.create_access_token("primary_owner")}
        result = self.client.post("/api/auth/change-password", headers=headers,
                                  json={"current_password": self.password, "new_password": self.password + "X"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.get("/api/users", headers=headers).status_code, 401)

    def test_primary_identity_and_no_startup_privilege_promotion(self):
        auth.create_user("secondary", self.password, "admin")
        self.assertFalse(auth.update_user_role("primary_owner", "viewer")[0])
        self.assertFalse(auth.delete_user_by_username("primary_owner"))
        auth.create_user("admin", self.password, "viewer")
        initialize_database()
        self.assertEqual(auth.get_user_by_username("admin")["role"], "viewer")

    def test_api_rate_limit_is_shared_between_clients(self):
        token, _ = generate_api_token("limited", rate_limit=1)
        headers = {"X-API-Key": token}
        response = self.client.get("/api/summary", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-RateLimit-Remaining"], "0")
        with TestClient(app) as second:
            response = second.get("/api/summary", headers=headers)
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)

    def test_explicit_invalid_credentials_do_not_fall_back_to_cookie(self):
        self.client.cookies.set("access_token", self.headers["Authorization"][7:])
        self.assertEqual(self.client.get("/api/users", headers={"X-API-Key": "invalid"}).status_code, 401)

    def test_health_and_ready_work_before_setup(self):
        with get_connection() as conn:
            conn.execute("DELETE FROM users")
            conn.execute('UPDATE installation_metadata SET admin_setup_completed=0 WHERE id=1')
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertTrue(self.client.get("/api/ready").json()["setup_required"])

    def test_investigations_require_auth_and_write_privileges(self):
        for url in ("/investigate", "/investigate?ioc=" + "a" * 64, "/api/investigate/history"):
            self.assertEqual(self.client.get(url).status_code, 401)
        auth.create_user("viewer", self.password, "viewer")
        headers = {"Authorization": "Bearer " + auth.create_access_token("viewer")}
        self.assertEqual(self.client.get("/api/investigate?ioc=" + "a" * 64, headers=headers).status_code, 403)
        self.assertEqual(self.client.get("/investigate?ioc=" + "a" * 64, headers=headers).status_code, 403)

    def test_ssrf_private_ipv6_and_dns_failure(self):
        for url in ("http://[::1]/", "http://[fd00::1]/", "http://[::ffff:127.0.0.1]/", "http://169.254.169.254/", "http://user:secret@example.com/"):
            self.assertFalse(is_safe_external_url(url)[0], url)
        with patch("socket.getaddrinfo", side_effect=socket.gaierror()):
            self.assertFalse(is_safe_external_url("https://not-resolved.example/")[0])
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ('8.8.8.8', 443)), (10, 1, 6, '', ('fd00::1', 443, 0, 0))]):
            self.assertFalse(is_safe_external_url("https://mixed.example/")[0])

    def test_socket_connects_to_checked_numeric_address(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ('8.8.8.8', 443))]), \
             patch("httpcore.SyncBackend.connect_tcp", return_value=MagicMock()) as connect:
            PublicNetworkBackend().connect_tcp("public.example", 443)
        self.assertEqual(connect.call_args.args[:2], ("8.8.8.8", 443))

    def test_redirect_to_metadata_is_blocked(self):
        response = httpx.Response(302, headers={"Location": "http://169.254.169.254/"}, request=httpx.Request("GET", "https://public.example"))
        transport = httpx.MockTransport(lambda request: response)
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ('8.8.8.8', 443))]), \
             patch("app.services.outbound_service.PublicHTTPTransport", return_value=transport):
            with self.assertRaises(ValueError):
                safe_request("GET", "https://public.example/", allow_redirects=True)

    def test_webhook_is_revalidated_at_dispatch(self):
        webhook_id = save_webhook({"name": "Unsafe imported record", "platform": "generic", "webhook_url": "http://[fd00::1]/"})
        self.assertFalse(send_test_notification(webhook_id))

    def test_mask_hides_all_paths_queries_and_userinfo(self):
        for url in ("https://example.com/private-secret", "https://example.com?token=private-secret", "https://user:private-secret@example.com/path"):
            self.assertNotIn("private-secret", mask_webhook_url(url))
            self.assertNotIn("user:", mask_webhook_url(url))

    def test_audit_concurrent_writes_and_ip_tampering(self):
        barrier = Barrier(6)
        def append(index):
            barrier.wait()
            return audit.log_audit_event("review", "admin", "CONCURRENT", resource_id=str(index), ip_address="8.8.8.8")
        with ThreadPoolExecutor(max_workers=6) as executor:
            ids = list(executor.map(append, range(6)))
        self.assertTrue(all(i > 0 for i in ids))
        self.assertTrue(audit.verify_audit_log_integrity()["is_valid"])
        with get_connection() as conn:
            conn.execute("UPDATE audit_logs SET ip_address='1.1.1.1' WHERE id=?", (ids[0],))
        self.assertFalse(audit.verify_audit_log_integrity()["is_valid"])

    def test_external_checkpoint_detects_tail_deletion(self):
        audit.log_audit_event("review", "admin", "FIRST")
        audit.log_audit_event("review", "admin", "SECOND")
        checkpoint = audit.verify_audit_log_integrity()["checkpoint"]
        with get_connection() as conn:
            conn.execute("DELETE FROM audit_logs WHERE id=?", (checkpoint["id"],))
        self.assertFalse(audit.verify_audit_log_integrity(checkpoint)["is_valid"])

    def test_legacy_audit_records_are_preserved_and_reported(self):
        fields = dict(prev_hash=audit.GENESIS_HASH, timestamp="2026-01-01", username="legacy", role="admin",
                      action="OLD", resource_type=None, resource_id=None, status="SUCCESS", details="old")
        digest = audit.compute_entry_hash(**fields)
        with get_connection() as conn:
            conn.execute("""INSERT INTO audit_logs(timestamp, username, role, action, status, details, prev_hash, integrity_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", tuple(fields[k] for k in ("timestamp", "username", "role", "action", "status", "details", "prev_hash")) + (digest,))
        audit.log_audit_event("review", "admin", "NEW")
        verification = audit.verify_audit_log_integrity()
        self.assertTrue(verification["is_valid"])
        self.assertEqual(verification["legacy_records"], 1)

    def test_unknown_intel_and_zero_scores_are_not_fabricated(self):
        self.assertIsNone(get_cve_details("CVE-9999-99999")["cvss_score"])
        with get_connection() as conn:
            conn.execute("INSERT INTO cves(cve_id, severity, cvss_score, epss_score) VALUES ('CVE-2021-44228', 'LOW', 0, 0)")
        data = get_cve_details("CVE-2021-44228")
        self.assertEqual((data["cvss_score"], data["epss_score"], data["severity"]), (0, 0, "LOW"))
        unknown = investigate_ioc("a" * 64)
        self.assertEqual(unknown["verdict"], "UNKNOWN")
        self.assertIn("Not queried", unknown["raw_details"]["vt_detection"])

    def test_ioc_matching_is_exact_and_dns_failure_is_safe(self):
        with get_connection() as conn:
            conn.execute("INSERT INTO threat_indicators(indicator_type,indicator_value,source) VALUES ('ip','11.2.3.45','test')")
        with patch("app.services.ioc_service.enrich_ip", return_value={}):
            self.assertEqual(investigate_ioc("1.2.3.4")["verdict"], "UNKNOWN")
        with patch("socket.gethostbyname_ex", side_effect=OSError("DNS unavailable")):
            response = self.client.get("/api/investigate?ioc=example.invalid", headers=self.headers)
        self.assertEqual(response.status_code, 200)

    def test_nvd_pagination_upserts_and_watermark(self):
        pages = [{"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-10000"}}, {"cve": {"id": "CVE-2026-10001"}}]},
                 {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-10002"}}]}]
        with patch("app.services.cve_service.fetch_json", side_effect=pages) as fetch, patch("app.services.cve_service.time.sleep"):
            self.assertEqual(fetch_and_store_cves(), 3)
        self.assertEqual(fetch.call_args_list[1].kwargs["params"]["startIndex"], 2)
        with patch("app.services.cve_service.fetch_json", return_value={"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-10000", "metrics": {"cvssMetricV40": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8}}]}}}]}):
            self.assertEqual(fetch_and_store_cves(), 0)
        with get_connection() as conn:
            self.assertEqual(conn.execute("SELECT cvss_score FROM cves WHERE cve_id='CVE-2026-10000'").fetchone()[0], 8)
            self.assertIsNotNone(conn.execute("SELECT value FROM app_settings WHERE key='nvd_last_sync'").fetchone())

    def test_incomplete_nvd_page_does_not_advance_sync(self):
        with patch("app.services.cve_service.fetch_json", return_value={"totalResults": 20, "vulnerabilities": []}):
            with self.assertRaises(ValueError):
                fetch_and_store_cves()
        with get_connection() as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM app_settings WHERE key='nvd_last_sync'").fetchone())

    def test_existing_epss_scores_are_updated(self):
        with get_connection() as conn:
            conn.execute("INSERT INTO cves(cve_id,epss_score) VALUES ('CVE-2026-10000',0.1)")
        with patch("app.services.cve_service.fetch_json", return_value={"data": [{"cve": "CVE-2026-10000", "epss": "0.9"}]}):
            self.assertEqual(fetch_epss_scores(), 1)
        with get_connection() as conn:
            self.assertEqual(conn.execute("SELECT epss_score FROM cves").fetchone()[0], 0.9)

    def test_complete_cisa_catalog_is_ingested_regardless_of_order(self):
        vulnerabilities = [{"cveID": f"CVE-2026-{10000+i}", "dateAdded": "2026-01-01"} for i in range(65)]
        with patch("app.services.cisa_service.fetch_json", return_value={"vulnerabilities": vulnerabilities}):
            self.assertEqual(fetch_and_store_cisa_kev(), 65)

    def test_refresh_lease_excludes_other_workers_and_manual_runs(self):
        with refresh_lease() as acquired:
            self.assertTrue(acquired)
            with refresh_lease() as other:
                self.assertFalse(other)
            self.assertEqual(run_feed_refresh()["status"], "busy")
        with refresh_lease() as acquired:
            self.assertTrue(acquired)

    def test_generated_password_obeys_policy_and_has_a_bound(self):
        auth.update_password_policy(min_length=24)
        password = self.client.get("/api/security/generate-password").json()["password"]
        self.assertTrue(auth.validate_password_against_policy(password)[0])
        self.assertEqual(len(password), 24)
        self.assertEqual(self.client.get("/api/security/generate-password?length=1000000000").status_code, 422)

    def test_rule_titles_are_only_data_not_javascript(self):
        title = "Review');globalThis.reviewXss=true;//"
        save_detection_rule({"title": title, "rule_type": "Sigma", "code_content": "title: example"})
        page = self.client.get("/rules").text
        self.assertNotIn("reviewXss", "\n".join(re.findall(r'onclick="([^"]+)"', page)))
        self.assertIn("data-rule-title=", page)

    def test_catalog_matches_actual_routes(self):
        for endpoint in get_api_endpoints_catalog():
            self.assertTrue(any(getattr(route, "path", None) == endpoint["path"] and endpoint["method"] in (getattr(route, "methods", None) or []) for route in app.routes), endpoint)

    def test_database_connections_are_closed(self):
        with get_connection() as conn:
            conn.execute("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

    def test_backup_is_consistent_and_never_overwrites(self):
        source = Path(os.environ["DATABASE_PATH"])
        output = source.parent / "review-backup.db"
        try:
            backup_database(source, output)
            with sqlite3.connect(output) as conn:
                self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(conn.execute("SELECT username FROM users WHERE is_primary=1").fetchone()[0], "primary_owner")
            with self.assertRaises(FileExistsError):
                backup_database(source, output)
        finally:
            output.unlink(missing_ok=True)

    def test_concurrent_setup_creates_only_one_primary(self):
        with get_connection() as conn:
            conn.execute("DELETE FROM users")
            conn.execute('UPDATE installation_metadata SET admin_setup_completed=0 WHERE id=1')
        barrier = Barrier(2)
        def setup(index):
            barrier.wait()
            try:
                auth.complete_initial_setup("owner" + str(index), self.password)
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sum(executor.map(setup, range(2))), 1)
        with get_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE is_primary=1").fetchone()[0], 1)

    def test_existing_database_migrates_without_promoting_named_viewer(self):
        legacy = Path(os.environ["DATABASE_PATH"]).parent / "legacy.db"
        try:
            with sqlite3.connect(legacy) as conn:
                conn.execute("""CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
                    password_hash TEXT, role TEXT, last_login TEXT, created_at TEXT, updated_at TEXT)""")
                conn.execute("INSERT INTO users(username,password_hash,role) VALUES ('custom_admin','unused','admin')")
                conn.execute("INSERT INTO users(username,password_hash,role) VALUES ('admin','unused','viewer')")
            with patch("app.database.DATABASE_PATH", legacy):
                initialize_database()
                self.assertTrue(auth.get_user_by_username("custom_admin")["is_primary"])
                self.assertEqual(auth.get_user_by_username("admin")["role"], "viewer")
                self.assertEqual(auth.get_user_by_username("custom_admin")["session_version"], 0)
        finally:
            legacy.unlink(missing_ok=True)

    def test_response_size_limit_and_https_downgrade(self):
        for response in (httpx.Response(200, content=b"oversized"), httpx.Response(302, headers={"Location": "http://public.example/"})):
            transport = httpx.MockTransport(lambda request: response)
            with patch("app.services.outbound_service.PublicHTTPTransport", return_value=transport):
                with self.assertRaises(ValueError):
                    safe_request("GET", "https://public.example/", allow_redirects=True, max_bytes=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
