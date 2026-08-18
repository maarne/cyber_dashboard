import requests

BASE_URL = "http://127.0.0.1:8000"

def test_threat_actors():
    session = requests.Session()

    print("1. Testing GET /api/threat-actors (All actors)...")
    res = session.get(f"{BASE_URL}/api/threat-actors")
    actors = res.json()
    print(f"Status: {res.status_code}, Total Actors: {len(actors)}")
    assert res.status_code == 200
    assert len(actors) >= 25, f"Expected at least 25 threat actors, got {len(actors)}"

    print("\n2. Testing search filter (e.g. 'Midnight Blizzard')...")
    res = session.get(f"{BASE_URL}/api/threat-actors", params={"search": "Midnight Blizzard"})
    found = res.json()
    print(f"Status: {res.status_code}, Found: {[a['name'] for a in found]}")
    assert res.status_code == 200
    assert len(found) >= 1
    assert "APT29" in found[0]["name"]

    print("\n3. Testing search filter for ransomware (e.g. 'LockBit' and 'Black Basta')...")
    res = session.get(f"{BASE_URL}/api/threat-actors", params={"search": "Black Basta"})
    found = res.json()
    print(f"Status: {res.status_code}, Found: {[a['name'] for a in found]}")
    assert res.status_code == 200
    assert len(found) >= 1
    assert "Black Basta" in found[0]["name"]

    print("\n4. Testing sector filter (e.g. 'Telecommunications')...")
    res = session.get(f"{BASE_URL}/api/threat-actors", params={"sector": "Telecommunications"})
    telecom_actors = res.json()
    print(f"Status: {res.status_code}, Total in Telecommunications sector: {len(telecom_actors)}")
    assert res.status_code == 200
    assert len(telecom_actors) >= 3

    print("\n5. Testing GET /actors HTML page route...")
    res = session.get(f"{BASE_URL}/actors")
    print(f"Status: {res.status_code}")
    assert res.status_code == 200
    assert "Threat Actors & Ransomware Groups" in res.text

    print("\n🎉 EXPANDED THREAT ACTORS TESTS PASSED!")

if __name__ == "__main__":
    test_threat_actors()
