import requests

BASE_URL = "http://127.0.0.1:8000"

def test_search_url():
    session = requests.Session()

    print("1. Testing GET /?search=CVE-2023-38831...")
    res = session.get(f"{BASE_URL}/", params={"search": "CVE-2023-38831"})
    print(f"Status: {res.status_code}")
    assert res.status_code == 200
    assert 'value="CVE-2023-38831"' in res.text
    assert 'CVE-2023-38831' in res.text

    print("\n2. Testing GET /?q=CVE-2021-44228...")
    res = session.get(f"{BASE_URL}/", params={"q": "CVE-2021-44228"})
    print(f"Status: {res.status_code}")
    assert res.status_code == 200
    assert 'value="CVE-2021-44228"' in res.text

    print("\n🎉 CVE SEARCH URL PARAMETER TESTS PASSED!")

if __name__ == "__main__":
    test_search_url()
