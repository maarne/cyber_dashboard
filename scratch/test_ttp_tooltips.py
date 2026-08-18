import requests

BASE_URL = "http://127.0.0.1:8000"

def test_ttp_tooltips():
    session = requests.Session()

    print("1. Testing GET /api/mitre-ttps/T1190...")
    res = session.get(f"{BASE_URL}/api/mitre-ttps/T1190")
    print(f"Status: {res.status_code}, Data: {res.json()}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "T1190"
    assert "Exploit Public-Facing Application" in data["name"]
    assert "Initial Access" in data["tactic"]
    assert "last_modified" in data

    print("\n2. Testing GET /actors HTML page for TTP hover popovers...")
    res = session.get(f"{BASE_URL}/actors")
    assert res.status_code == 200
    assert "ttp-tooltip-wrapper" in res.text
    assert "ttp-popover" in res.text
    assert "Last Modified" in res.text

    print("\n3. Testing GET /rules HTML page for TTP hover popovers...")
    res = session.get(f"{BASE_URL}/rules")
    assert res.status_code == 200
    assert "ttp-tooltip-wrapper" in res.text
    assert "ttp-popover" in res.text

    print("\n🎉 MITRE TTP HOVER TOOLTIPS TESTS PASSED!")

if __name__ == "__main__":
    test_ttp_tooltips()
