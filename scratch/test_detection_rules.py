import requests

BASE_URL = "http://127.0.0.1:8000"

def test_detection_rules():
    session = requests.Session()

    print("1. Testing GET /api/detection-rules (Expanded rule dataset)...")
    res = session.get(f"{BASE_URL}/api/detection-rules")
    rules = res.json()
    print(f"Status: {res.status_code}, Total Rules: {len(rules)}")
    assert res.status_code == 200
    assert len(rules) >= 15

    print("\n2. Testing filter by rule_type=SIGMA...")
    res = session.get(f"{BASE_URL}/api/detection-rules", params={"rule_type": "SIGMA"})
    sigma_rules = res.json()
    print(f"Status: {res.status_code}, Sigma Rules Count: {len(sigma_rules)}")
    assert res.status_code == 200
    assert len(sigma_rules) >= 10
    assert all(r["rule_type"] == "Sigma" for r in sigma_rules)

    print("\n3. Testing filter by rule_type=YARA...")
    res = session.get(f"{BASE_URL}/api/detection-rules", params={"rule_type": "YARA"})
    yara_rules = res.json()
    print(f"Status: {res.status_code}, YARA Rules Count: {len(yara_rules)}")
    assert res.status_code == 200
    assert len(yara_rules) >= 5
    assert all(r["rule_type"] == "YARA" for r in yara_rules)

    print("\n4. Testing Deployment Guide content...")
    log4j_rules = [r for r in rules if "Log4j" in r["title"] and r.get("deployment_guide")]
    log4j_rule = log4j_rules[0]
    guide_text = log4j_rule.get("deployment_guide") or ""
    print(f"Log4j Rule Guide length: {len(guide_text)}")
    assert len(guide_text) > 100
    assert "Splunk" in guide_text

    print("\n5. Testing GET /rules HTML page route...")
    res = session.get(f"{BASE_URL}/rules")
    print(f"Status: {res.status_code}")
    assert res.status_code == 200
    assert "How to Deploy" in res.text

    print("\n🎉 EXPANDED DETECTION RULE & DEPLOYMENT GUIDE TESTS PASSED!")

if __name__ == "__main__":
    test_detection_rules()
