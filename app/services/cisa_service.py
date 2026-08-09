# ============================================================
# app/services/cisa_service.py — CISA KEV Catalog Fetcher
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This service fetches the CISA Known Exploited Vulnerabilities
# (KEV) catalog and stores entries in our SQLite database.
#
# WHAT IS CISA KEV?
# -----------------
# CISA (Cybersecurity & Infrastructure Security Agency) is
# a U.S. government agency. They maintain a catalog of
# vulnerabilities that are CONFIRMED to be actively exploited
# by attackers in the real world. If a CVE appears in this
# catalog, it means attackers are using it RIGHT NOW.
#
# Federal agencies are REQUIRED to patch KEV vulnerabilities
# by the listed due date. Private organizations should treat
# these as urgent priorities too.
#
# PYTHON CONCEPTS COVERED:
# - Working with JSON responses
# - Slicing lists with [:50] syntax
# - String manipulation
# ============================================================

import httpx
from app.config import CISA_KEV_URL, HTTP_TIMEOUT_SECONDS
from app.database import get_connection


def fetch_and_store_cisa_kev():
    """
    Fetch the CISA Known Exploited Vulnerabilities catalog
    and save entries to the database.

    HOW THIS FUNCTION WORKS:
    ------------------------
    1. Download the full KEV JSON catalog from CISA's website
    2. Extract the list of vulnerabilities
    3. Take the most recent 50 entries
    4. Insert each one into our cisa_exploits table
    5. Return the count of newly saved records

    Returns:
        int: Number of new CISA KEV entries saved.
    """

    # ----------------------------------------------------------
    # STEP 1: Fetch the CISA KEV catalog
    # ----------------------------------------------------------
    try:
        response = httpx.get(
            CISA_KEV_URL,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()

    except Exception as error:
        print(f"❌ Error fetching CISA KEV catalog: {error}")
        return 0

    # ----------------------------------------------------------
    # STEP 2: Extract the vulnerabilities list
    # ----------------------------------------------------------
    # The CISA JSON structure has a key called "vulnerabilities"
    # that contains a list of all known exploited vulns.
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        print("ℹ️  No vulnerabilities found in CISA KEV catalog.")
        return 0

    # ----------------------------------------------------------
    # STEP 3: Take the most recent 50 entries
    # ----------------------------------------------------------
    # PYTHON CONCEPT — List Slicing:
    #   my_list[-50:] takes the LAST 50 items from a list.
    #
    #   Breakdown:
    #     my_list[start:end]  → items from index start to end-1
    #     my_list[-50:]       → last 50 items (negative = from end)
    #     my_list[:10]        → first 10 items
    #
    #   The CISA list is sorted oldest-first, so [-50:] gives us
    #   the 50 most recently added vulnerabilities.
    recent_vulns = vulnerabilities[-50:]

    # PYTHON CONCEPT — reversed():
    #   reversed() flips the order of a list so the newest
    #   entries appear first. We wrap it in list() to convert
    #   the reversed iterator back into a regular list.
    recent_vulns = list(reversed(recent_vulns))

    # ----------------------------------------------------------
    # STEP 4: Insert each entry into the database
    # ----------------------------------------------------------
    saved_count = 0

    with get_connection() as conn:
        cursor = conn.cursor()

        for vuln in recent_vulns:
            # Extract fields from the vulnerability dictionary.
            # Each vulnerability has keys like:
            #   "cveID", "vendorProject", "product", etc.
            cve_id = vuln.get("cveID", "")
            vulnerability_name = vuln.get("vulnerabilityName", "")
            vendor_project = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            date_added = vuln.get("dateAdded", "")
            short_description = vuln.get("shortDescription", "")
            required_action = vuln.get("requiredAction", "")
            due_date = vuln.get("dueDate", "")

            # Skip entries without a CVE ID
            if not cve_id:
                continue

            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO cisa_exploits
                    (cve_id, vulnerability_name, vendor_project, product,
                     date_added, short_description, required_action, due_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_id, vulnerability_name, vendor_project, product,
                    date_added, short_description, required_action, due_date,
                ))

                if cursor.rowcount > 0:
                    saved_count += 1

            except Exception as db_error:
                print(f"⚠️  Error saving CISA KEV {cve_id}: {db_error}")

        conn.commit()

        # Log the fetch timestamp
        cursor.execute("""
            INSERT OR REPLACE INTO fetch_log (source_name, last_fetch, status, record_count)
            VALUES (?, datetime('now'), 'success', ?)
        """, ("cisa_kev", saved_count))
        conn.commit()

    print(f"✅ Saved {saved_count} new CISA KEV entries to the database.")
    return saved_count
