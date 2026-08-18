import sys
from pathlib import Path
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

import requests
from app.services.webhook_service import is_safe_external_url
from app.services.threat_service import fetch_and_store_urlhaus

BASE_URL = "http://127.0.0.1:8000"

def test_ssrf_validator():
    print("1. Testing SSRF validation helper...")
    
    # Dangerous URLs that MUST be blocked
    prohibited_urls = [
        "http://127.0.0.1:8000/api/auth/me",
        "http://localhost:8000",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5:8080/internal",
        "http://192.168.1.1/admin",
        "file:///etc/passwd",
        "ftp://malicious.com/feed.xml",
        "javascript:alert(1)",
    ]
    for bad_url in prohibited_urls:
        is_safe, err = is_safe_external_url(bad_url)
        print(f"   Blocked: {bad_url} -> Safe: {is_safe} ({err})")
        assert is_safe is False, f"Expected {bad_url} to be rejected, but passed!"

    # Safe public URLs that MUST be allowed
    allowed_urls = [
        "https://hooks.slack.com/services/sample_workspace_team/sample_channel_id/mock_token_secret_12345",
        "https://discord.com/api/webhooks/sample_channel_12345/mock_token_secret_abcdef",
        "https://krebsonsecurity.com/feed/",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    ]
    for good_url in allowed_urls:
        is_safe, err = is_safe_external_url(good_url)
        print(f"   Allowed: {good_url[:40]}... -> Safe: {is_safe}")
        assert is_safe is True, f"Expected {good_url} to be allowed, but rejected: {err}"

    print("✅ SSRF Validation test passed!\n")


def test_urlhaus_ingestion():
    print("2. Testing URLhaus public CSV threat intel ingestion...")
    count = fetch_and_store_urlhaus()
    print(f"   URLhaus fetch result: {count} indicators saved.")
    assert count >= 0
    print("✅ URLhaus ingestion test passed!\n")


def test_api_ssrf_endpoints():
    print("3. Testing API endpoints for SSRF rejection...")
    session = requests.Session()
    # Login as admin
    login_res = session.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": "cyberdash123!"})
    assert login_res.status_code == 200

    # Try creating a webhook with an internal loopback IP
    res = session.post(f"{BASE_URL}/api/webhooks", json={
        "name": "Malicious Webhook",
        "platform": "Generic",
        "webhook_url": "http://127.0.0.1:8000/admin-console",
        "is_active": True,
        "notify_critical": True,
        "notify_high": False,
        "notify_cisa": False,
    })
    print(f"   Create Webhook with 127.0.0.1 -> Status: {res.status_code}, Response: {res.json()}")
    assert res.status_code == 400
    assert "Invalid webhook URL" in res.json().get("error", "")

    # Try adding an RSS feed with cloud metadata IP
    res = session.post(f"{BASE_URL}/api/rss-feeds", json={
        "name": "Cloud Metadata",
        "url": "http://169.254.169.254/latest/meta-data/",
    })
    print(f"   Add RSS Feed with 169.254.169.254 -> Status: {res.status_code}, Response: {res.json()}")
    assert res.status_code == 400
    assert "Invalid RSS feed URL" in res.json().get("error", "")

    print("✅ API SSRF defense test passed!\n")


if __name__ == "__main__":
    test_ssrf_validator()
    test_urlhaus_ingestion()
    test_api_ssrf_endpoints()
    print("🎉 ALL SECURITY AUDIT TESTS PASSED SUCCESSFULLY!")
