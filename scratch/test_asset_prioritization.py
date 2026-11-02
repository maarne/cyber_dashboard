"""Feature 1 acceptance/regression tests; never uses the workspace database."""
from scratch import test_support

import csv
import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from unittest.mock import patch

os.environ["FEATURE_ASSET_PRIORITIZATION"] = "true"

from fastapi.testclient import TestClient
from app.database import get_connection, initialize_database
from app.main import app, require_admin, require_analyst_or_admin, require_authenticated_user
from app.services import asset_service as assets, auth_service as auth
from app.services.api_token_service import generate_api_token, get_api_endpoints_catalog
from app.services.audit_service import verify_audit_log_integrity
from app.services.cve_service import record_fetch, fetch_epss_scores
from app.services.prioritization_service import list_priorities


class AssetPrioritizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        password = auth.generate_secure_random_password(18)
        auth.complete_initial_setup("owner", password)
        for role in ("analyst", "viewer"):
            auth.create_user(role, password, role)
        cls.headers = {role: {"Authorization": "Bearer " + auth.create_access_token(name)}
                       for role, name in (("admin", "owner"), ("analyst", "analyst"), ("viewer", "viewer"))}
        cls.actor = {"username": "owner", "role": "admin", "user_id": auth.get_user_by_username("owner")["id"]}

    def setUp(self):
        test_support.assert_test_database()
        with get_connection() as conn:
            for table in ("asset_import_previews", "asset_assessment_events", "asset_cve_assessments", "asset_software", "asset_tags", "assets", "audit_logs", "cves", "cisa_exploits", "fetch_log"):
                conn.execute(f"DELETE FROM {table}")
            conn.execute("UPDATE asset_inventory_state SET revision=0")
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()

    def request(self, method, path, data=None, role="admin", expected=200):
        response = self.client.request(method, path, headers=self.headers[role], **({"json": data} if data is not None else {}))
        self.assertEqual(response.status_code, expected, response.text)
        self.assertIn("no-store", response.headers["cache-control"])
        return response.json()

    def asset(self, **overrides):
        return self.request("POST", "/api/assets", {"external_id": "SERVER-01", "name": "Private sentinel asset", "exposure": "internet", "criticality": 4, **overrides}, expected=201)

    def associate(self, asset_id, **overrides):
        return self.request("POST", f"/api/assets/{asset_id}/cves", {"cve_id": "CVE-2026-10000", "evidence_note": "Vendor advisory checked", **overrides}, expected=201)

    def csv(self, rows=None):
        if rows is None:
            return assets.csv_template()
        output = io.StringIO(); writer = csv.writer(output); writer.writerow(assets.CSV_FIELDS)
        writer.writerows(rows); return output.getvalue()

    def test_migration_idempotence_preserves_legacy_and_foreign_keys(self):
        a = self.asset(); assessment = self.associate(a["id"])
        with get_connection() as conn:
            before = {table: [tuple(r) for r in conn.execute(f"SELECT * FROM {table}")] for table in ("users", "assets", "asset_cve_assessments", "audit_logs")}
        initialize_database(); initialize_database()
        with get_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 3)
            self.assertFalse(conn.execute("PRAGMA foreign_key_check").fetchall())
            for table, values in before.items():
                self.assertEqual([tuple(r) for r in conn.execute(f"SELECT * FROM {table}")], values)
        self.assertTrue(assessment["id"])

    def test_upgrade_from_actual_pre_feature_schema_and_rollback(self):
        legacy = Path(test_support._sandbox.name) / "legacy-upgrade.db"
        from app import database
        with patch.object(database, "DATABASE_PATH", legacy):
            with patch("app.migrations.apply_migrations"):
                initialize_database()
            with get_connection() as conn:
                self.assertNotIn("epss_fetched_at", {r["name"] for r in conn.execute("PRAGMA table_info(cves)")})
                conn.execute("INSERT INTO cves(cve_id,cvss_score,epss_score) VALUES ('CVE-2025-10000',0,0)")
                conn.execute("INSERT INTO fetch_log(source_name,status,last_fetch) VALUES ('cisa_kev','success','2026-10-31')")
            # An interrupted migration rolls back schema and ledger together.
            from app.migrations import apply_migrations
            with self.assertRaises(RuntimeError):
                with get_connection() as conn:
                    conn.execute("BEGIN IMMEDIATE"); apply_migrations(conn); raise RuntimeError("interrupted startup")
            with get_connection() as conn:
                self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='assets'").fetchone())
            initialize_database()
            with get_connection() as conn:
                row = conn.execute("SELECT * FROM cves WHERE cve_id='CVE-2025-10000'").fetchone()
                self.assertEqual(row["epss_score"], 0); self.assertIsNone(row["epss_fetched_at"])
                self.assertEqual(conn.execute("SELECT last_success FROM fetch_log WHERE source_name='cisa_kev'").fetchone()[0], '2026-10-31')
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 0)

    def test_feature_off_is_404_even_before_setup(self):
        code = """from scratch import test_support
import os
os.environ['FEATURE_ASSET_PRIORITIZATION']='false'
from app.database import initialize_database
initialize_database()
from app.main import app
from fastapi.testclient import TestClient
c=TestClient(app)
for p in ('/assets','/assets/1','/priorities','/api/assets','/api/priorities','/api/asset-assessments/1'):
 r=c.get(p); assert r.status_code==404,(p,r.text); assert 'no-store' in r.headers['cache-control']
assert '/api/assets' not in app.openapi()['paths']
"""
        result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_privacy_roles_catalog_and_templates(self):
        a = self.asset(name='<img src=x onerror="alert(1)">')
        for path in ("/assets", f"/assets/{a['id']}", "/priorities", "/api/assets", "/api/priorities", "/api/assets/export"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        home = self.client.get("/").text
        self.assertNotIn("Private sentinel asset", home)
        self.assertNotIn('href="/assets"', home)
        for path in ("/assets", f"/assets/{a['id']}", "/priorities"):
            response = self.client.get(path, headers=self.headers["viewer"])
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn('<img src=x onerror="alert(1)">', response.text)
        self.request("POST", "/api/assets", {"external_id": "other", "name": "Other"}, role="viewer", expected=403)
        for role in ("analyst", "viewer"):
            self.request("GET", "/api/assets/export", role=role, expected=403)
            self.request("POST", "/api/assets/import/preview", {"csv_content": self.csv()}, role=role, expected=403)
            self.request("POST", f"/api/assets/{a['id']}/archive", {"expected_version": 1}, role=role, expected=403)
        catalog = get_api_endpoints_catalog()
        by_route = {(r["path"], r["method"]): r["auth_required"] for r in catalog}
        self.assertEqual(by_route[("/api/assets/export", "GET")], "Admin")
        self.assertEqual(by_route[("/api/assets", "POST")], "Analyst / Admin")
        self.assertEqual(by_route[("/api/priorities", "GET")], "Viewer (authenticated)")

    def test_csrf_cookie_origin_and_explicit_credentials(self):
        self.client.cookies.set("access_token", self.headers["admin"]["Authorization"][7:])
        data = {"external_id": "one", "name": "One"}
        self.assertEqual(self.client.post("/api/assets", json=data).status_code, 403)
        csrf = self.client.get("/api/assets/session").json()["csrf_token"]
        for headers in ({"X-CSRF-Token": csrf}, {"X-CSRF-Token": csrf, "Origin": "https://evil.example"}, {"X-CSRF-Token": "bad", "Origin": "http://testserver"}):
            self.assertEqual(self.client.post("/api/assets", json=data, headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/api/assets", json=data, headers={"X-CSRF-Token": csrf, "Origin": "http://testserver"}).status_code, 201)
        self.assertEqual(self.client.post("/api/assets", json={**data, "external_id": "two"}, headers={"X-API-Key": "invalid"}).status_code, 401)
        self.request("POST", "/api/assets", {**data, "external_id": "three"}, expected=201)
        token, _ = generate_api_token("machine", role="analyst")
        response = self.client.post("/api/assets", json={**data, "external_id": "machine"}, headers={"X-API-Key": token})
        self.assertEqual(response.status_code, 201, response.text)
        with get_connection() as conn:
            row = conn.execute("SELECT * FROM assets WHERE external_id='machine'").fetchone()
            self.assertIsNotNone(row["created_by_token_id"]); self.assertIsNone(row["created_by_user_id"])

    def test_crud_versions_validation_and_literal_search(self):
        a = self.asset(tags=["SOC", "soc"], owner_team="100%_SOC")
        self.assertEqual(a["external_id"], "server-01"); self.assertEqual(a["tags"], ["soc"])
        self.request("PATCH", f"/api/assets/{a['id']}", {"expected_version": 1, "criticality": "3"}, expected=422)
        self.request("PATCH", f"/api/assets/{a['id']}", {"expected_version": 1, "name": None}, expected=422)
        self.request("PATCH", f"/api/assets/{a['id']}", {"expected_version": 1, "name": "Updated"})
        self.request("PATCH", f"/api/assets/{a['id']}", {"expected_version": 1, "name": "Stale"}, expected=409)
        self.request("POST", "/api/assets", {"external_id": "server-01", "name": "Dup"}, expected=409)
        self.assertEqual(self.request("GET", "/api/assets?search=%25_")["total"], 1)
        self.assertEqual(self.request("GET", "/api/assets?tag=soc")["total"], 1)
        self.assertEqual(self.request("GET", "/api/assets?limit=101", expected=422)["detail"][0]["type"], "less_than_equal")

    def test_software_links_assessment_history_and_archive(self):
        a = self.asset(); other = self.asset(external_id="other")
        s = self.request("POST", f"/api/assets/{a['id']}/software", {"vendor": "Vendor", "product": "Product", "version": "1"}, expected=201)
        self.request("POST", f"/api/assets/{a['id']}/software", {"vendor": "VENDOR", "product": "product", "version": "1"}, expected=409)
        self.request("POST", f"/api/assets/{other['id']}/cves", {"cve_id": "CVE-2026-10000", "evidence_note": "Test", "software_id": s["id"]}, expected=422)
        v = self.associate(a["id"], software_id=s["id"])
        self.request("DELETE", f"/api/assets/{a['id']}/software/{s['id']}", {"expected_version": 1}, expected=409)
        self.request("PATCH", f"/api/asset-assessments/{v['id']}", {"expected_version": 1, "status": "remediated"}, expected=422)
        self.request("PATCH", f"/api/asset-assessments/{v['id']}", {"expected_version": 1, "software_id": None, "status": "remediated", "reason": "Patched"})
        self.request("PATCH", f"/api/asset-assessments/{v['id']}", {"expected_version": 1, "reason": "Stale"}, expected=409)
        self.request("DELETE", f"/api/assets/{a['id']}/software/{s['id']}", {"expected_version": 1})
        events = self.request("GET", f"/api/assets/{a['id']}/events")["items"]
        self.assertEqual(len(events), 2); self.assertEqual(json.loads(events[0]["before_json"])["status"], "open")
        self.request("POST", f"/api/assets/{a['id']}/archive", {"expected_version": 1})
        self.request("PATCH", f"/api/asset-assessments/{v['id']}", {"expected_version": 2, "status": "open"}, expected=409)
        self.assertEqual(self.request("GET", "/api/assets?archived=true")["total"], 1)
        self.request("POST", f"/api/assets/{a['id']}/archive", {"expected_version": 2, "archived": False})
        self.assertEqual(len(self.request("GET", f"/api/assets/{a['id']}/events")["items"]), 2)

    def test_unknown_zero_max_scores_kev_freshness_and_expiry(self):
        a = self.asset(); v = self.associate(a["id"])
        row = list_priorities()["items"][0]
        self.assertIsNone(row["score"]); self.assertEqual(set(row["missing_inputs"]), {"cvss", "epss", "kev"})
        with get_connection() as conn:
            conn.execute("INSERT INTO cves(cve_id,cvss_score,epss_score,epss_fetched_at) VALUES (?,0,0,datetime('now'))", (v["cve_id"],))
        record_fetch("cisa_kev", 0)
        self.assertEqual(list_priorities()["items"][0]["score"], 20)
        with get_connection() as conn:
            conn.execute("UPDATE cves SET cvss_score=10,epss_score=1,epss_fetched_at='2000-01-01'")
            conn.execute("INSERT INTO cisa_exploits(cve_id) VALUES (?)", (v["cve_id"],))
        record_fetch("cisa_kev", 0, "failed")
        row = list_priorities()["items"][0]; self.assertEqual(row["score"], 100)
        self.assertTrue(row["urgent_kev"]); self.assertIn("epss_stale", row["freshness_warnings"])
        self.assertIn("kev_latest_refresh_failed", row["freshness_warnings"])
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        self.request("PATCH", f"/api/asset-assessments/{v['id']}", {"expected_version": 1, "status": "accepted_risk", "reason": "Temporary exception", "accepted_risk_expires_at": future})
        self.assertEqual(list_priorities()["total"], 0)
        with get_connection() as conn:
            conn.execute("UPDATE asset_cve_assessments SET accepted_risk_expires_at='2000-01-01T00:00:00Z'")
        row = list_priorities()["items"][0]; self.assertTrue(row["risk_acceptance_expired"])
        self.assertEqual(row["status"], "accepted_risk"); self.assertEqual(row["effective_status"], "open")
        self.request("POST", f"/api/assets/{a['id']}/archive", {"expected_version": 1})
        self.assertEqual(list_priorities()["total"], 0); self.assertEqual(list_priorities(include_archived=True)["total"], 1)

    def test_sorting_filters_and_epss_ingestion_timestamp(self):
        a = self.asset(environment="production", tags=["soc"])
        v = self.associate(a["id"])
        other = self.asset(external_id="b", exposure="unknown"); self.associate(other["id"], cve_id="CVE-2026-20000")
        with get_connection() as conn:
            conn.execute("INSERT INTO cves(cve_id,cvss_score,epss_score) VALUES (?,10,1)", (v["cve_id"],))
            conn.execute("INSERT INTO cisa_exploits(cve_id) VALUES ('CVE-2026-20000')")
        self.assertEqual(list_priorities()["items"][0]["cve_id"], "CVE-2026-20000")
        self.assertEqual(list_priorities(environment="production", tag="soc")["total"], 1)
        self.assertEqual(list_priorities(urgent_only=True)["total"], 1)
        with patch("app.services.cve_service.fetch_json", return_value={"data": [{"cve": v["cve_id"], "epss": "0"}]}):
            fetch_epss_scores()
        row = list_priorities(asset_id=a["id"])["items"][0]
        self.assertEqual(row["inputs"]["epss"], 0); self.assertIsNotNone(row["epss_fetched_at"])

    def test_import_preview_commit_binding_merge_and_normalized_duplicates(self):
        rows = list(csv.reader(io.StringIO(self.csv())))[1:]
        rows.append(rows[0].copy()); rows[1][8] = "EXAMPLE VENDOR"
        content = self.csv(rows)
        p = self.request("POST", "/api/assets/import/preview", {"csv_content": content})
        self.assertEqual(p["summary"]["software_added"], 1)
        self.assertEqual(self.request("GET", "/api/assets")["total"], 0)
        result = self.request("POST", "/api/assets/import/commit", {"preview_token": p["preview_token"]})
        self.assertEqual(result["software_added"], 1)
        self.request("POST", "/api/assets/import/commit", {"preview_token": p["preview_token"]}, expected=409)
        a = self.request("GET", "/api/assets")["items"][0]
        v = self.request("GET", f"/api/assets/{a['id']}/cves")["items"][0]
        self.request("PATCH", f"/api/asset-assessments/{v['id']}", {"expected_version": 1, "status": "not_affected", "reason": "Validated exception", "evidence_note": "Preserve this evidence"})
        p = assets.preview_import(content, self.actor)
        other_actor = {**self.actor, "user_id": auth.get_user_by_username("analyst")["id"], "username": "analyst"}
        with self.assertRaises(Exception) as exc: assets.commit_import(p["preview_token"], other_actor)
        self.assertEqual(exc.exception.status_code, 404)
        assets.commit_import(p["preview_token"], self.actor)
        current = self.request("GET", f"/api/assets/{a['id']}/cves")["items"][0]
        self.assertEqual(current["evidence_note"], "Preserve this evidence"); self.assertEqual(current["status"], "not_affected")

    def test_import_stale_expired_conflicts_limits_and_atomic_audit_rollback(self):
        p = assets.preview_import(self.csv(), self.actor)
        self.asset()
        with self.assertRaises(Exception) as exc: assets.commit_import(p["preview_token"], self.actor)
        self.assertEqual(exc.exception.status_code, 409)
        p = assets.preview_import(self.csv(), self.actor)
        with get_connection() as conn: conn.execute("UPDATE asset_import_previews SET expires_at=0")
        with self.assertRaises(Exception): assets.commit_import(p["preview_token"], self.actor)
        rows = list(csv.reader(io.StringIO(self.csv())))[1:]; rows.append(rows[0].copy()); rows[1][2] = "conflict"
        self.request("POST", "/api/assets/import/preview", {"csv_content": self.csv(rows)}, expected=422)
        self.request("POST", "/api/assets/import/preview", {"csv_content": "x" * (1048576 + 1)}, expected=422)
        self.request("POST", "/api/assets/import/preview", {"csv_content": self.csv([rows[0]] * 1001)}, expected=413)
        with patch.object(assets, "MAX_ASSETS", 1):
            self.request("POST", "/api/assets/import/preview", {"csv_content": self.csv()}, expected=409)
        p = assets.preview_import(self.csv(), self.actor)
        with patch.object(assets, "log_audit_event", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaises(RuntimeError): assets.commit_import(p["preview_token"], self.actor)
            with self.assertRaises(RuntimeError): assets.create_asset({"external_id": "rollback", "name": "Rollback"}, self.actor)
        self.assertEqual(self.request("GET", "/api/assets")["total"], 1)
        with get_connection() as conn:
            self.assertIsNone(conn.execute("SELECT consumed_at FROM asset_import_previews").fetchone()[0])
        assets.commit_import(p["preview_token"], self.actor)
        self.assertTrue(verify_audit_log_integrity()["is_valid"])

    def test_streamed_body_limit_export_safety_and_quota(self):
        response = self.client.post("/api/assets", headers={**self.headers["admin"], "Content-Type": "application/json"}, content=iter([b"x" * 40000, b"x" * 40000]))
        self.assertEqual(response.status_code, 413)
        a = self.asset(name=" =HYPERLINK(\"https://evil.example\")", owner_team="@evil")
        self.associate(a["id"])
        data = self.request("GET", "/api/assets/export")
        self.assertEqual(data["schema_version"], 1); self.assertEqual(len(data["assessments"]), 1)
        text = self.client.get("/api/assets/export?format=csv", headers=self.headers["admin"]).text
        parsed = list(csv.DictReader(io.StringIO(text)))[0]
        self.assertTrue(parsed["name"].startswith("'")); self.assertTrue(parsed["owner_team"].startswith("'"))
        self.assertNotIn("password_hash", json.dumps(data)); self.assertNotIn("access_token", json.dumps(data))
        with patch.object(assets, "MAX_SOFTWARE", 0):
            self.request("POST", f"/api/assets/{a['id']}/software", {"vendor": "V", "product": "P", "version": "1"}, expected=409)
        with patch.object(assets, "MAX_ASSESSMENTS", 0):
            self.request("POST", f"/api/assets/{a['id']}/cves", {"cve_id": "CVE-2026-20000", "evidence_note": "Check"}, expected=409)

    def test_origin_override_session_bound_csrf_and_utc_expiry(self):
        self.client.cookies.set("access_token", self.headers["admin"]["Authorization"][7:])
        csrf = self.client.get("/api/assets/session").json()["csrf_token"]
        payload = {"external_id": "origin", "name": "Origin test"}
        with patch("app.asset_security.PUBLIC_BASE_URL", "https://dashboard.example"):
            response = self.client.post("/api/assets", json=payload, headers={"X-CSRF-Token": csrf, "Origin": "http://testserver"})
            self.assertEqual(response.status_code, 403)
            response = self.client.post("/api/assets", json=payload, headers={"X-CSRF-Token": csrf, "Origin": "https://dashboard.example"})
            self.assertEqual(response.status_code, 201)
        self.client.cookies.set("access_token", auth.create_access_token("owner"))
        self.assertEqual(self.client.post("/api/assets", json=payload, headers={"X-CSRF-Token": csrf, "Origin": "http://testserver"}).status_code, 403)
        a = self.asset(); v = self.associate(a["id"])
        expiry = (datetime.now(timezone(timedelta(hours=3))) + timedelta(days=1)).isoformat()
        record = self.request("PATCH", f"/api/asset-assessments/{v['id']}", {"expected_version": 1, "status": "accepted_risk", "reason": "Temporary", "accepted_risk_expires_at": expiry})
        self.assertEqual(datetime.fromisoformat(record["accepted_risk_expires_at"]).utcoffset(), timedelta(0))
        self.assertEqual(datetime.fromisoformat(record["accepted_risk_expires_at"]), datetime.fromisoformat(expiry))

    def test_real_audit_append_failure_rolls_back_and_errors_are_private(self):
        with get_connection() as conn:
            conn.execute("""CREATE TRIGGER reject_asset_audit BEFORE INSERT ON audit_logs
                WHEN NEW.action LIKE 'ASSET_%' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END""")
        try:
            self.request("POST", "/api/assets", {"external_id": "rollback", "name": "No partial record"}, expected=409)
            self.assertEqual(self.request("GET", "/api/assets")["total"], 0)
        finally:
            with get_connection() as conn: conn.execute("DROP TRIGGER reject_asset_audit")
        with patch.object(assets, "log_audit_event", side_effect=RuntimeError("private failure")):
            with TestClient(app, raise_server_exceptions=False) as client:
                response = client.post('/api/assets', json={"external_id": "error", "name": "Error"}, headers=self.headers['admin'])
                self.assertEqual(response.status_code, 500)
                self.assertIn('no-store', response.headers['cache-control'])
                self.assertNotIn('private failure', response.text)

    def test_concurrent_edits_and_one_use_import(self):
        a = self.asset(); barrier = Barrier(2)
        def edit(name):
            barrier.wait()
            try:
                assets.update_asset(a["id"], {"expected_version": 1, "name": name}, self.actor); return 200
            except Exception as exc: return exc.status_code
        with ThreadPoolExecutor(2) as pool: self.assertEqual(sorted(pool.map(edit, ("one", "two"))), [200, 409])
        p = assets.preview_import(self.csv(), self.actor); barrier = Barrier(2)
        def commit(_):
            barrier.wait()
            try: assets.commit_import(p["preview_token"], self.actor); return 200
            except Exception as exc: return exc.status_code
        with ThreadPoolExecutor(2) as pool: self.assertEqual(sorted(pool.map(commit, (1, 2))), [200, 409])
        self.assertTrue(verify_audit_log_integrity()["is_valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
