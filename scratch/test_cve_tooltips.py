import requests

BASE_URL = "http://127.0.0.1:8000"

def test_cve_tooltips():
    session = requests.Session()

    print("1. Testing GET /api/cve-intel/CVE-2023-4966...")
    res = session.get(f"{BASE_URL}/api/cve-intel/CVE-2023-4966")
    print(f"Status: {res.status_code}, Data: {res.json()}")
    assert res.status_code == 200
    data = res.json()
    assert data["cve_id"] == "CVE-2023-4966"
    assert "Citrix" in data["name"]
    assert data["severity"] == "CRITICAL"
    assert data["cvss_score"] >= 9.0
    assert data["is_cisa_kev"] is True

    print("\n2. Testing GET /actors HTML page for CVE hover popovers...")
    res = session.get(f"{BASE_URL}/actors")
    assert res.status_code == 200
    assert "cve-tooltip-wrapper" in res.text
    assert "cve-popover" in res.text
    assert "CitrixBleed" in res.text or "Log4j" in res.text or "WinRAR" in res.text

    print("\n3. Testing GET /rules HTML page for CVE hover popovers...")
    res = session.get(f"{BASE_URL}/rules")
    assert res.status_code == 200
    assert "cve-tooltip-wrapper" in res.text
    assert "cve-popover" in res.text

    print("\n🎉 CVE HOVER TOOLTIPS TESTS PASSED!")

if __name__ == "__main__":
    test_cve_tooltips()
