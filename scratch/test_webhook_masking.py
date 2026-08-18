from app.services.webhook_service import get_all_webhooks, save_webhook, update_webhook, get_webhook_by_id, mask_webhook_url

def test_masking():
    print("1. Testing mask_webhook_url utility...")
    url1 = "https://hooks.slack.com/services/sample_workspace_team/sample_channel_id/mock_token_secret_12345"
    masked1 = mask_webhook_url(url1)
    print(f"Original: {url1}\nMasked:   {masked1}")
    assert "mock_token" not in masked1
    assert "••••••••" in masked1

    print("\n2. Testing save_webhook and get_all_webhooks...")
    test_id = save_webhook({
        "name": "Secret Test Webhook",
        "platform": "slack",
        "webhook_url": "https://hooks.slack.com/services/sample_test_token_alpha_999",
        "is_active": True
    })
    
    all_webhooks = get_all_webhooks()
    test_wh = next((w for w in all_webhooks if w["id"] == test_id), None)
    assert test_wh is not None
    print(f"Stored URL: {test_wh['webhook_url']}")
    print(f"Masked URL: {test_wh['masked_url']}")
    assert "sample_test_token" not in test_wh["masked_url"]
    assert "••••••••" in test_wh["masked_url"]

    print("\n3. Testing update_webhook with masked URL placeholder...")
    update_webhook(test_id, {
        "name": "Secret Test Webhook Updated",
        "platform": "slack",
        "webhook_url": test_wh["masked_url"], # Passed back from edit form
        "is_active": True
    })

    updated_wh = get_webhook_by_id(test_id)
    print(f"URL after update with masked placeholder: {updated_wh['webhook_url']}")
    assert updated_wh["webhook_url"] == "https://hooks.slack.com/services/sample_test_token_alpha_999"
    assert updated_wh["name"] == "Secret Test Webhook Updated"

    print("\n🎉 ALL WEBHOOK MASKING TESTS PASSED!")

if __name__ == "__main__":
    test_masking()
