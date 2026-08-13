# ============================================================
# app/services/webhook_service.py — Webhook Notification Service
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This file handles everything related to webhook notifications:
#   1. CRUD operations (Create, Read, Update, Delete) for webhooks
#   2. Formatting notification messages for different platforms
#   3. Sending HTTP POST requests to webhook URLs
#
# WHAT IS A WEBHOOK?
# ------------------
# A webhook is a URL that accepts incoming HTTP POST requests.
# When we send a specially formatted JSON payload to a webhook
# URL, the receiving platform (Slack, Discord, Teams, etc.)
# displays it as a message in a channel.
#
# Think of it like sending an email, but instead of an email
# address, you use a URL, and instead of email body text,
# you send JSON data.
#
# PYTHON CONCEPTS COVERED:
# - Making HTTP POST requests with httpx
# - Formatting JSON payloads (nested dictionaries)
# - Platform-specific if/elif/else branching
# - CRUD database operations (INSERT, SELECT, UPDATE, DELETE)
# - Error handling per-webhook (one failure doesn't block others)
# - The datetime module for timestamps
# ============================================================

import httpx
from datetime import datetime, timezone

from app.database import get_connection
from app.config import HTTP_TIMEOUT_SECONDS


# ============================================================
# CRUD OPERATIONS — Create, Read, Update, Delete
# ============================================================
# These functions manage webhook records in the SQLite database.
# "CRUD" is a common pattern in web development:
#   C = Create (INSERT)
#   R = Read   (SELECT)
#   U = Update (UPDATE)
#   D = Delete (DELETE)
# ============================================================


def mask_webhook_url(url: str) -> str:
    """
    Mask a webhook URL to prevent secret tokens/keys from being exposed in UI/DOM.
    Example: https://hooks.slack.com/services/T00/B00/XXXXXX -> https://hooks.slack.com/services/••••••••
    """
    if not url:
        return ""
    try:
        parts = url.split("://", 1)
        if len(parts) == 2:
            scheme, rest = parts
            path_parts = rest.split("/", 2)
            if len(path_parts) >= 2:
                domain_and_base = f"{scheme}://{path_parts[0]}/{path_parts[1]}"
                return f"{domain_and_base}/••••••••"
            return f"{scheme}://{path_parts[0]}/••••••••"
    except Exception:
        pass
    return "https://••••••••"


def get_all_webhooks():
    """
    Retrieve all webhook configurations from the database.

    Returns:
        list: A list of dictionaries, each representing a webhook.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM webhooks
            ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()

    webhooks = []
    for row in rows:
        item = dict(row)
        item["masked_url"] = mask_webhook_url(item.get("webhook_url", ""))
        webhooks.append(item)
    return webhooks


def get_webhook_by_id(webhook_id):
    """
    Retrieve a single webhook by its ID.

    Args:
        webhook_id: The integer ID of the webhook to retrieve.

    Returns:
        dict or None: The webhook as a dictionary, or None if not found.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = cursor.fetchone()

    return dict(row) if row else None


def save_webhook(data):
    """
    Insert a new webhook configuration into the database.

    PYTHON CONCEPT — Dictionary Access:
        data["name"] retrieves the value associated with the key "name".
        If the key doesn't exist, Python raises a KeyError.
        data.get("key", default) is safer — it returns the default
        value instead of raising an error.

    Args:
        data: A dictionary (or Pydantic model) with webhook fields.

    Returns:
        int: The ID of the newly created webhook.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # INSERT INTO adds a new row to the webhooks table.
        # The ? placeholders are filled with the values from
        # the tuple, in order. This prevents SQL injection.
        cursor.execute("""
            INSERT INTO webhooks
                (name, platform, webhook_url, is_active,
                 notify_critical_cves, notify_high_cves, notify_cisa_exploits)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data["name"],
            data["platform"],
            data["webhook_url"],
            1 if data.get("is_active", True) else 0,
            1 if data.get("notify_critical_cves", True) else 0,
            1 if data.get("notify_high_cves", True) else 0,
            1 if data.get("notify_cisa_exploits", True) else 0,
        ))

        conn.commit()

        # cursor.lastrowid gives us the ID of the row we just inserted.
        # This is useful for returning the new webhook's ID to the caller.
        return cursor.lastrowid


def update_webhook(webhook_id, data):
    """
    Update an existing webhook configuration.
    """
    webhook_url = data["webhook_url"]
    if "••••" in webhook_url:
        existing = get_webhook_by_id(webhook_id)
        if existing:
            webhook_url = existing["webhook_url"]

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE webhooks
            SET name = ?,
                platform = ?,
                webhook_url = ?,
                is_active = ?,
                notify_critical_cves = ?,
                notify_high_cves = ?,
                notify_cisa_exploits = ?
            WHERE id = ?
        """, (
            data["name"],
            data["platform"],
            webhook_url,
            1 if data.get("is_active", True) else 0,
            1 if data.get("notify_critical_cves", True) else 0,
            1 if data.get("notify_high_cves", True) else 0,
            1 if data.get("notify_cisa_exploits", True) else 0,
            webhook_id,
        ))
        conn.commit()

        # cursor.rowcount tells us how many rows were affected.
        # If it's 0, no row matched the WHERE clause (bad ID).
        return cursor.rowcount > 0


def delete_webhook(webhook_id):
    """
    Delete a webhook configuration from the database.

    SQL CONCEPT — DELETE FROM ... WHERE:
        DELETE FROM webhooks WHERE id = ?
        Removes the row where the id matches. Without the WHERE
        clause, DELETE would remove ALL rows (dangerous!).

    Args:
        webhook_id: The ID of the webhook to delete.

    Returns:
        bool: True if a row was deleted, False if not found.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        conn.commit()
        return cursor.rowcount > 0


def toggle_webhook(webhook_id):
    """
    Toggle a webhook between active (1) and inactive (0).

    SQL CONCEPT — Toggle with NOT:
        SET is_active = NOT is_active
        If is_active is 1, NOT 1 = 0 (disable it).
        If is_active is 0, NOT 0 = 1 (enable it).

    Args:
        webhook_id: The ID of the webhook to toggle.

    Returns:
        bool: True if toggled successfully.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE webhooks
            SET is_active = NOT is_active
            WHERE id = ?
        """, (webhook_id,))
        conn.commit()
        return cursor.rowcount > 0


# ============================================================
# NOTIFICATION FORMATTING
# ============================================================
# Each platform (Slack, Discord, Teams, Generic) expects a
# different JSON payload format. These functions build the
# correct payload for each platform.
#
# PYTHON CONCEPT — Dictionary Nesting:
#   JSON payloads are just nested Python dictionaries.
#   {"key": {"nested_key": [1, 2, 3]}}
#   Python dicts map directly to JSON objects.
# ============================================================


def _format_slack_payload(title, message, items):
    """
    Build a Slack Block Kit payload.

    Slack webhooks expect a JSON body with optional "blocks"
    for rich formatting. See: https://api.slack.com/block-kit

    Args:
        title: The notification headline (e.g. "🚨 New CRITICAL CVEs")
        message: A summary line (e.g. "3 new critical vulnerabilities found")
        items: A list of strings describing each item

    Returns:
        dict: A Slack-compatible JSON payload.
    """
    # Build a bullet list of items (max 10 to avoid huge messages)
    item_text = "\n".join(f"• {item}" for item in items[:10])
    if len(items) > 10:
        item_text += f"\n_...and {len(items) - 10} more_"

    return {
        "text": f"{title}: {message}",  # Fallback for simple clients
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": title}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": item_text}
            },
        ]
    }


def _format_discord_payload(title, message, items):
    """
    Build a Discord embed payload.

    Discord webhooks accept "embeds" for rich formatting.
    See: https://discord.com/developers/docs/resources/message

    Returns:
        dict: A Discord-compatible JSON payload.
    """
    item_text = "\n".join(f"• {item}" for item in items[:10])
    if len(items) > 10:
        item_text += f"\n...and {len(items) - 10} more"

    return {
        "content": f"**{title}**",
        "embeds": [
            {
                "title": title,
                "description": f"{message}\n\n{item_text}",
                "color": 15158332,  # Red color in decimal
                "footer": {"text": "CyberDash Security Dashboard"},
            }
        ]
    }


def _format_teams_payload(title, message, items):
    """
    Build a Microsoft Teams MessageCard payload.

    Teams webhooks use the "MessageCard" format (legacy) or
    Adaptive Cards. We use MessageCard for broad compatibility.
    See: https://learn.microsoft.com/en-us/outlook/actionable-messages/

    Returns:
        dict: A Teams-compatible JSON payload.
    """
    item_text = "\n\n".join(f"- {item}" for item in items[:10])
    if len(items) > 10:
        item_text += f"\n\n...and {len(items) - 10} more"

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": title,
        "sections": [
            {
                "activityTitle": title,
                "text": f"{message}\n\n{item_text}",
            }
        ]
    }


def _format_generic_payload(title, message, items):
    """
    Build a simple generic JSON payload.

    This works with any webhook endpoint that accepts JSON.
    The payload is intentionally simple and self-documenting.

    Returns:
        dict: A plain JSON payload.
    """
    return {
        "title": title,
        "message": message,
        "items": items[:20],
        "source": "CyberDash Security Dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _build_payload(platform, title, message, items):
    """
    Route to the correct platform formatter.

    PYTHON CONCEPT — if/elif/else Branching:
        This pattern checks the platform string and calls
        the matching formatter. If none match, we fall back
        to the generic format. This is a common alternative
        to a switch/case statement (which Python 3.10+ has
        as match/case).

    Args:
        platform: One of "slack", "discord", "teams", "generic"
        title: Notification headline
        message: Summary line
        items: List of item description strings

    Returns:
        dict: The formatted JSON payload for the platform.
    """
    if platform == "slack":
        return _format_slack_payload(title, message, items)
    elif platform == "discord":
        return _format_discord_payload(title, message, items)
    elif platform == "teams":
        return _format_teams_payload(title, message, items)
    else:
        return _format_generic_payload(title, message, items)


# ============================================================
# SENDING NOTIFICATIONS
# ============================================================


def _send_single_notification(webhook, title, message, items):
    """
    Send a notification to a single webhook endpoint.

    PYTHON CONCEPT — httpx.post():
        httpx.post(url, json=payload) sends an HTTP POST request
        with the payload serialized as JSON. The "json=" parameter
        automatically sets the Content-Type header to
        "application/json" and converts the Python dict to JSON.

    PYTHON CONCEPT — try/except for Error Handling:
        Network requests can fail for many reasons (timeout,
        bad URL, server error). We wrap the call in try/except
        so a failure doesn't crash the entire notification loop.

    Args:
        webhook: A dictionary with webhook configuration.
        title: Notification headline.
        message: Summary text.
        items: List of item description strings.

    Returns:
        bool: True if the notification was sent successfully.
    """
    payload = _build_payload(webhook["platform"], title, message, items)

    try:
        # httpx.post() sends the HTTP POST request.
        # timeout=10 means give up after 10 seconds.
        response = httpx.post(
            webhook["webhook_url"],
            json=payload,
            timeout=HTTP_TIMEOUT_SECONDS,
        )

        # HTTP status codes in the 200-299 range mean success.
        # response.is_success is True when the status code is 2xx.
        if response.is_success:
            print(f"  ✅ Webhook '{webhook['name']}' ({webhook['platform']}): sent OK")

            # Update the last_notified timestamp in the database
            # so we can implement rate limiting later.
            _update_last_notified(webhook["id"])
            return True
        else:
            print(f"  ❌ Webhook '{webhook['name']}': HTTP {response.status_code}")
            return False

    except httpx.TimeoutException:
        print(f"  ❌ Webhook '{webhook['name']}': timed out")
        return False
    except Exception as e:
        print(f"  ❌ Webhook '{webhook['name']}': {e}")
        return False


def _update_last_notified(webhook_id):
    """Update the last_notified timestamp for a webhook."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE webhooks
            SET last_notified = datetime('now')
            WHERE id = ?
        """, (webhook_id,))
        conn.commit()


def notify_all_webhooks(new_critical_cves=None, new_high_cves=None, new_cisa_exploits=None):
    """
    Send notifications to all active webhooks based on what's new.

    This function is called after a data refresh. It checks what
    new data was found and sends appropriate notifications to each
    active webhook based on its notification preferences.

    PYTHON CONCEPT — Conditional Logic:
        Each webhook has preferences (notify_critical_cves, etc.).
        We check these preferences before sending, so each webhook
        only receives the types of alerts its owner wants.

    Args:
        new_critical_cves: List of dicts for new CRITICAL CVEs (or None).
        new_high_cves: List of dicts for new HIGH CVEs (or None).
        new_cisa_exploits: List of dicts for new CISA entries (or None).

    Returns:
        dict: Summary of notifications sent and failed.
    """
    new_critical_cves = new_critical_cves or []
    new_high_cves = new_high_cves or []
    new_cisa_exploits = new_cisa_exploits or []

    # If there's nothing new, skip entirely
    if not new_critical_cves and not new_high_cves and not new_cisa_exploits:
        print("📭 No new items to notify about.")
        return {"sent": 0, "failed": 0, "skipped": 0}

    # Get all active webhooks from the database
    all_webhooks = get_all_webhooks()
    active_webhooks = [w for w in all_webhooks if w["is_active"]]

    if not active_webhooks:
        print("📭 No active webhooks configured.")
        return {"sent": 0, "failed": 0, "skipped": 0}

    print(f"\n📣 Sending notifications to {len(active_webhooks)} active webhook(s)...")

    sent = 0
    failed = 0
    skipped = 0

    for webhook in active_webhooks:

        # --- CRITICAL CVE notifications ---
        if new_critical_cves and webhook["notify_critical_cves"]:
            items = [
                f"{cve['cve_id']}: {(cve.get('description') or 'No description')[:100]}"
                for cve in new_critical_cves
            ]
            success = _send_single_notification(
                webhook,
                "🚨 New CRITICAL CVEs Detected",
                f"{len(new_critical_cves)} new critical vulnerability(ies) found.",
                items,
            )
            sent += 1 if success else 0
            failed += 0 if success else 1

        # --- HIGH CVE notifications ---
        if new_high_cves and webhook["notify_high_cves"]:
            items = [
                f"{cve['cve_id']}: {(cve.get('description') or 'No description')[:100]}"
                for cve in new_high_cves
            ]
            success = _send_single_notification(
                webhook,
                "⚠️ New HIGH Severity CVEs",
                f"{len(new_high_cves)} new high-severity vulnerability(ies) found.",
                items,
            )
            sent += 1 if success else 0
            failed += 0 if success else 1

        # --- CISA exploit notifications ---
        if new_cisa_exploits and webhook["notify_cisa_exploits"]:
            items = [
                f"{exp['cve_id']}: {exp.get('vulnerability_name') or 'Unknown'}"
                for exp in new_cisa_exploits
            ]
            success = _send_single_notification(
                webhook,
                "🔴 New CISA Active Exploits",
                f"{len(new_cisa_exploits)} new actively exploited vulnerability(ies) added to CISA KEV.",
                items,
            )
            sent += 1 if success else 0
            failed += 0 if success else 1

        # If this webhook didn't match any notification type
        if (not (new_critical_cves and webhook["notify_critical_cves"])
                and not (new_high_cves and webhook["notify_high_cves"])
                and not (new_cisa_exploits and webhook["notify_cisa_exploits"])):
            skipped += 1

    results = {"sent": sent, "failed": failed, "skipped": skipped}
    print(f"📣 Notification results: {results}")
    return results


def send_test_notification(webhook_id):
    """
    Send a test notification to a specific webhook.

    This is used by the Settings page "Test" button to verify
    that a webhook URL is correctly configured and reachable.

    Args:
        webhook_id: The ID of the webhook to test.

    Returns:
        bool: True if the test notification was delivered.
    """
    webhook = get_webhook_by_id(webhook_id)
    if not webhook:
        return False

    return _send_single_notification(
        webhook,
        "🧪 CyberDash Test Notification",
        "This is a test notification from CyberDash. If you see this, your webhook is working!",
        [
            "CVE-0000-0000: This is a sample vulnerability (CRITICAL)",
            "CVE-0000-0001: Another sample vulnerability (HIGH)",
            "CISA KEV: Sample actively exploited vulnerability",
        ],
    )
