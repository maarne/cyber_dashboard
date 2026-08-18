import sys
sys.path.insert(0, '/home/maarne/apps/antigravity/cyber_dashboard')

import requests
from app.database import initialize_database
from app.services.rule_service import seed_default_detection_rules, get_all_detection_rules

BASE_URL = "http://127.0.0.1:8000"

def test_deduplication():
    print("1. Running database deduplication cleanup and seed...")
    initialize_database()
    seed_default_detection_rules()

    print("\n2. Fetching all detection rules...")
    rules = get_all_detection_rules()
    print(f"Total Rules Count: {len(rules)}")
    
    titles = [r["title"].strip().lower() for r in rules]
    unique_titles = set(titles)
    
    print(f"Unique Titles Count: {len(unique_titles)}")
    assert len(titles) == len(unique_titles), f"Duplicates found! Total: {len(titles)}, Unique: {len(unique_titles)}"
    print(f"✅ Verified 0 duplicates! ({len(rules)} unique rules in database)")

    print("\n3. Testing re-seeding multiple times...")
    seed_default_detection_rules()
    seed_default_detection_rules()
    
    rules_after = get_all_detection_rules()
    print(f"Total Rules Count after multiple seeds: {len(rules_after)}")
    assert len(rules_after) == len(rules), f"Re-seeding created duplicates! Initial: {len(rules)}, After: {len(rules_after)}"

    print("\n4. Testing GET /api/detection-rules API endpoint...")
    res = requests.get(f"{BASE_URL}/api/detection-rules")
    api_rules = res.json()
    print(f"API returned {len(api_rules)} unique detection rules.")
    assert res.status_code == 200
    assert len(api_rules) == len(rules)

    print("\n🎉 DEDUPLICATION TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    test_deduplication()
