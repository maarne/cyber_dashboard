import sys
from scratch.legacy_support import authenticated_session
from unittest.mock import patch
from app.services.ioc_service import classify_ioc, investigate_ioc, get_recent_investigations

BASE_URL = "http://127.0.0.1:8000"

def test_ioc_classification():
    print("1. Testing IOC Classifier...")
    assert classify_ioc("185.220.101.5") == "ipv4"
    assert classify_ioc("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "ipv6"
    assert classify_ioc("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert classify_ioc("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") == "sha256"
    assert classify_ioc("evil-botnet.ru") == "domain"
    assert classify_ioc("https://evil-botnet.ru/payload.exe") == "url"
    assert classify_ioc("invalid??ioc!!") == "unknown"
    print("✅ Classification tests passed!\n")


def test_ioc_investigation_service():
    print("2. Testing IOC Investigation service directly...")
    
    # This SHA-256 identifies EICAR, not WannaCry.
    dossier_hash = investigate_ioc("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert dossier_hash["ioc_type"] == "sha256"
    assert dossier_hash["verdict"] == "CLEAN"
    assert dossier_hash["threat_score"] == 0
    assert "EICAR" in dossier_hash["raw_details"]["malware_family"]
    assert "VirusTotal" in dossier_hash["pivots"]
    print("   ✅ EICAR test hash investigation passed.")

    # Test IP
    with patch("app.services.ioc_service.enrich_ip", return_value={"country": "Unknown"}):
        dossier_ip = investigate_ioc("185.220.101.5")
    assert dossier_ip["ioc_type"] == "ipv4"
    assert "network" in dossier_ip
    assert "pivots" in dossier_ip
    print("   ✅ IP investigation passed.\n")


def test_investigate_api_endpoints():
    print("3. Testing FastAPI /api/investigate endpoints...")
    session = authenticated_session()

    # GET /api/investigate?ioc=...
    res = session.get(f"{BASE_URL}/api/investigate", params={"ioc": "44d88612fea8a8f36de82e1278abb02f"})
    assert res.status_code == 200
    data = res.json()
    assert data["ioc_type"] == "md5"
    assert data["verdict"] == "CLEAN"
    assert "EICAR" in data["raw_details"]["malware_family"]

    # GET /api/investigate/history
    res = session.get(f"{BASE_URL}/api/investigate/history")
    assert res.status_code == 200
    history = res.json()
    assert len(history) >= 1
    assert any(h["indicator"] == "44d88612fea8a8f36de82e1278abb02f" for h in history)
    print("   ✅ API endpoints passed.\n")


def test_investigate_html_page():
    print("4. Testing GET /investigate HTML page...")
    session = authenticated_session()

    # Empty page
    res = session.get(f"{BASE_URL}/investigate")
    assert res.status_code == 200
    assert "Threat Intelligence &amp; IOC Investigator" in res.text or "Threat Intelligence & IOC Investigator" in res.text

    # Page with IOC query
    with patch("app.services.ioc_service.enrich_ip", return_value={"country": "Unknown"}):
        res = session.get(f"{BASE_URL}/investigate", params={"ioc": "185.220.101.5"})
    assert res.status_code == 200
    assert "185.220.101.5" in res.text
    assert "THREAT SCORE" in res.text
    assert "Network Telemetry" in res.text
    print("   ✅ HTML page rendering passed.\n")


if __name__ == "__main__":
    test_ioc_classification()
    test_ioc_investigation_service()
    test_investigate_api_endpoints()
    test_investigate_html_page()
    print("🎉 ALL IOC INVESTIGATOR TESTS PASSED SUCCESSFULLY!")
