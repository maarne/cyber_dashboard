# ============================================================
# app/services/threat_service.py — Abuse.ch Threat Intel Fetcher
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This service fetches threat intelligence data from Abuse.ch,
# a nonprofit that tracks malicious URLs and botnet infrastructure.
#
# DATA SOURCES:
# - URLhaus: Tracks URLs used to distribute malware
# - Feodo Tracker: Tracks botnet Command & Control (C2) servers
#
# WHAT IS AN "INDICATOR OF COMPROMISE" (IoC)?
# -------------------------------------------
# An IoC is a piece of evidence that something malicious has
# happened or is happening. Examples:
#   - A URL that downloads malware
#   - An IP address running a botnet command server
#   - A file hash of a known virus
#
# Security teams use IoC lists to block malicious traffic
# and detect compromised systems on their networks.
#
# PYTHON CONCEPTS COVERED:
# - Sending HTTP POST requests (vs GET)
# - Processing JSON API responses
# - Parsing plain-text line-by-line
# - The enumerate() function
# - Conditional logic with if/elif/else
# ============================================================

import csv
import io
import httpx
from app.config import URLHAUS_RECENT_URL, URLHAUS_API_KEY, FEODO_TRACKER_URL, HTTP_TIMEOUT_SECONDS
from app.database import get_connection


def fetch_and_store_urlhaus():
    """
    Fetch recent malicious URLs from URLhaus and save them to the database.

    Supports both:
    1. The public recent CSV download feed (no authentication required)
    2. Authenticated API key requests if configured in URLHAUS_API_KEY

    Returns:
        int: Number of new threat indicators saved.
    """
    headers = {}
    if URLHAUS_API_KEY:
        headers["Auth-Key"] = URLHAUS_API_KEY

    try:
        response = httpx.get(
            URLHAUS_RECENT_URL,
            headers=headers,
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
        )
        response.raise_for_status()
        raw_content = response.text

    except Exception as error:
        print(f"❌ Error fetching URLhaus data: {error}")
        return 0

    saved_count = 0

    # ----------------------------------------------------------
    # Check if response is JSON (API format) or CSV (download format)
    # ----------------------------------------------------------
    if raw_content.strip().startswith("{") and "urls" in raw_content:
        try:
            data = response.json()
            urls_list = data.get("urls", [])[:30]
            with get_connection() as conn:
                cursor = conn.cursor()
                for url_entry in urls_list:
                    indicator_value = url_entry.get("url", "")
                    threat_type = url_entry.get("threat", "malware_download")
                    date_added = url_entry.get("date_added", "")
                    status = url_entry.get("url_status", "active")

                    if not indicator_value:
                        continue
                    if len(indicator_value) > 500:
                        indicator_value = indicator_value[:500]

                    cursor.execute("""
                        INSERT OR IGNORE INTO threat_indicators
                        (indicator_type, indicator_value, threat_type, source, date_added, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, ("url", indicator_value, threat_type, "URLhaus", date_added, status))
                    if cursor.rowcount > 0:
                        saved_count += 1
                conn.commit()
            print(f"✅ Saved {saved_count} new URLhaus indicators to the database.")
            return saved_count
        except Exception as e:
            print(f"⚠️ Error parsing URLhaus JSON: {e}")

    # Parse CSV format
    csv_file = io.StringIO(raw_content)
    reader = csv.reader(csv_file)

    with get_connection() as conn:
        cursor = conn.cursor()
        for row in reader:
            # Skip empty lines and comment lines starting with '#'
            if not row or row[0].startswith("#"):
                continue

            # CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            if len(row) >= 6:
                date_added = row[1].strip()
                indicator_value = row[2].strip()
                status = row[3].strip()
                threat_type = row[5].strip() if row[5].strip() else "malware_download"

                if not indicator_value:
                    continue
                if len(indicator_value) > 500:
                    indicator_value = indicator_value[:500]

                try:
                    cursor.execute("""
                        INSERT OR IGNORE INTO threat_indicators
                        (indicator_type, indicator_value, threat_type, source, date_added, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, ("url", indicator_value, threat_type, "URLhaus", date_added, status))
                    if cursor.rowcount > 0:
                        saved_count += 1
                except Exception as db_error:
                    print(f"⚠️ Error saving URLhaus indicator: {db_error}")

            if saved_count >= 30:
                break

        conn.commit()

    print(f"✅ Saved {saved_count} new URLhaus indicators to the database.")
    return saved_count


def fetch_and_store_feodo():
    """
    Fetch botnet C2 IP addresses from Feodo Tracker and save
    them to the database.

    The Feodo Tracker provides a plain-text IP blocklist
    (not JSON). Each line is either a comment (starting with #)
    or an IP address.

    PYTHON CONCEPTS COVERED:
    - Parsing plain-text responses (vs JSON)
    - Splitting strings into lines with .splitlines()
    - The .startswith() string method
    - Skipping lines with "continue"

    Returns:
        int: Number of new botnet C2 IPs saved.
    """

    try:
        response = httpx.get(
            FEODO_TRACKER_URL,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        # Unlike JSON APIs, this endpoint returns plain text.
        # response.text gives us the raw text content as a string
        # (response.json() would fail here because it's not JSON).
        raw_text = response.text

    except Exception as error:
        print(f"❌ Error fetching Feodo Tracker data: {error}")
        return 0

    # ----------------------------------------------------------
    # STEP: Parse the plain-text IP list
    # ----------------------------------------------------------
    # .splitlines() splits a string into a list of lines.
    # For example:
    #   "line1\nline2\nline3".splitlines()
    #   → ["line1", "line2", "line3"]
    lines = raw_text.splitlines()

    saved_count = 0

    with get_connection() as conn:
        cursor = conn.cursor()

        # PYTHON CONCEPT — enumerate():
        #   enumerate(list) gives us both the INDEX and the VALUE
        #   of each item as we loop through the list.
        #
        #   for index, value in enumerate(["a", "b", "c"]):
        #       print(index, value)
        #   Output:
        #       0 a
        #       1 b
        #       2 c
        #
        #   We use the index here just for counting, but it's
        #   very useful when you need to know the position of
        #   an item in a list.
        for line_number, line in enumerate(lines):
            # .strip() removes whitespace from both ends of the string
            line = line.strip()

            # Skip empty lines and comment lines.
            # PYTHON CONCEPT — .startswith():
            #   "hello".startswith("he")  → True
            #   "hello".startswith("wo")  → False
            #   Lines starting with "#" are comments in this format.
            if not line or line.startswith("#"):
                continue

            # At this point, the line should be a bare IP address
            # like "1.2.3.4"
            ip_address = line

            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO threat_indicators
                    (indicator_type, indicator_value, threat_type, source, status)
                    VALUES (?, ?, ?, ?, ?)
                """, ("ip", ip_address, "botnet_c2", "Feodo Tracker", "active"))

                if cursor.rowcount > 0:
                    saved_count += 1

            except Exception as db_error:
                print(f"⚠️  Error saving Feodo IP {ip_address}: {db_error}")

        conn.commit()

    print(f"✅ Saved {saved_count} new Feodo Tracker IPs to the database.")
    return saved_count


def fetch_all_threat_intel():
    """
    Convenience function that fetches data from ALL threat
    intelligence sources.

    This is a simple "wrapper" function that calls other
    functions in sequence and returns the total count.

    Returns:
        int: Total number of new threat indicators saved.
    """
    total = 0
    total += fetch_and_store_urlhaus()
    total += fetch_and_store_feodo()
    return total
