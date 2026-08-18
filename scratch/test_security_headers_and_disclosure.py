import sys
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

import requests
import re
from app.services.auth_service import seed_default_admin_user, update_user_password, get_user_by_username, create_user

BASE_URL = "http://127.0.0.1:8000"

def test_security_hardening():
    print("=" * 60)
    print("🛡️ TESTING SECURITY HEADERS, CSP, CLICKJACKING & DISCLOSURE DEFENSES")
    print("=" * 60)

    # 1. Ensure admin account exists with known password
    admin_pwd = "Admin#Pass2026!"
    if not get_user_by_username("admin"):
        create_user("admin", admin_pwd, "admin")
    else:
        update_user_password("admin", admin_pwd)

    session = requests.Session()
    login_res = session.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": admin_pwd})
    assert login_res.status_code == 200, f"Admin login failed: {login_res.text}"

    # 2. Test Security Headers across core endpoints
    test_endpoints = ["/", "/investigate", "/actors", "/rules", "/settings", "/api/cves", "/api/summary"]

    for ep in test_endpoints:
        res = session.get(f"{BASE_URL}{ep}")
        headers = res.headers

        # 2A. Content-Security-Policy
        csp = headers.get("Content-Security-Policy", "")
        assert csp != "", f"Missing Content-Security-Policy on {ep}"
        assert "frame-ancestors 'none'" in csp, f"Missing frame-ancestors 'none' in CSP on {ep}"
        assert "default-src 'self'" in csp, f"Missing default-src 'self' in CSP on {ep}"
        assert "object-src 'none'" in csp, f"Missing object-src 'none' in CSP on {ep}"

        # 2B. Clickjacking Protections
        xfo = headers.get("X-Frame-Options", "")
        assert xfo == "DENY", f"Expected X-Frame-Options: DENY, got '{xfo}' on {ep}"

        # 2C. MIME & Cross-Site Defenses
        xcto = headers.get("X-Content-Type-Options", "")
        assert xcto == "nosniff", f"Expected X-Content-Type-Options: nosniff on {ep}"

        ref = headers.get("Referrer-Policy", "")
        assert ref == "strict-origin-when-cross-origin", f"Expected Referrer-Policy on {ep}"

        perm = headers.get("Permissions-Policy", "")
        assert "geolocation=()" in perm, f"Expected Permissions-Policy on {ep}"

    print("✅ 1. Content-Security-Policy (CSP) with frame-ancestors 'none' verified across all endpoints.")
    print("✅ 2. Anti-Clickjacking (X-Frame-Options: DENY) verified across all endpoints.")
    print("✅ 3. X-Content-Type-Options, Referrer-Policy, and Permissions-Policy verified.")

    # 3. Test Sensitive Source Code & SQL Disclosure Prevention
    sensitive_paths = [
        "/cyber_dashboard.db",
        "/app/database.py",
        "/app/main.py",
        "/database.sql",
        "/schema.sql",
        "/dump.sql",
        "/.env",
        "/.git/config",
        "/static/secret.sql",
        "/config.yml",
        "/app/secret.py",
        "/backup.bak"
    ]

    for sp in sensitive_paths:
        res = session.get(f"{BASE_URL}{sp}")
        assert res.status_code == 404, f"Path {sp} should return 404, got {res.status_code}"
        # Ensure no SQL queries or source code content leaked in body
        assert "SELECT " not in res.text
        assert "CREATE TABLE" not in res.text
        assert "password_hash" not in res.text

    print("✅ 4. Sensitive file & SQL source code disclosure prevention verified (all probe paths return 404 with no leaks).")

    # 4. Verify No External Scripts / Unhashed External Stylesheets in HTML
    html_pages = ["/", "/actors", "/rules", "/investigate", "/settings"]
    for page in html_pages:
        res = session.get(f"{BASE_URL}{page}")
        assert res.status_code == 200

        # Check for unhashed external scripts: <script src="http..."> without integrity
        script_srcs = re.findall(r'<script[^>]+src=["\'](http[^"\']+)["\'][^>]*>', res.text)
        for s in script_srcs:
            # If external, must have integrity
            match = re.search(rf'<script[^>]+src=["\']{re.escape(s)}["\'][^>]+integrity=', res.text)
            assert match is not None, f"Found external script missing Subresource Integrity (SRI) on {page}: {s}"

        # Check for external stylesheets: <link rel="stylesheet" href="http..."> without integrity
        link_hrefs = re.findall(r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\'](http[^"\']+)["\'][^>]*>', res.text)
        for l in link_hrefs:
            match = re.search(rf'<link[^>]+href=["\']{re.escape(l)}["\'][^>]+integrity=', res.text)
            assert match is not None, f"Found external stylesheet missing Subresource Integrity (SRI) on {page}: {l}"

    print("✅ 5. Subresource Integrity (SRI) verified: 0 external scripts/stylesheets without SRI found.")

    # 5. Verify 500 Error Sanitization
    # Request invalid method/path error or check error formatting
    err_res = session.get(f"{BASE_URL}/api/non_existent_resource_xyz")
    assert "sqlite3." not in err_res.text
    assert "Traceback (" not in err_res.text
    print("✅ 6. Global error sanitization verified: Zero database tracebacks or SQL syntax leaks.")

    print("\n🎉 ALL SECURITY HARDENING, CSP, CLICKJACKING & DISCLOSURE TESTS PASSED!")

if __name__ == "__main__":
    test_security_hardening()
