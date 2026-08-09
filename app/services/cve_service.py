# ============================================================
# app/services/cve_service.py — NVD Vulnerability Fetcher
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This service fetches vulnerability data from the National
# Vulnerability Database (NVD) API and stores it in our
# local SQLite database.
#
# WHAT IS THE NVD?
# ----------------
# The NVD (https://nvd.nist.gov) is the U.S. government's
# official repository of software vulnerabilities. Every
# vulnerability gets a unique "CVE" identifier (e.g.,
# CVE-2024-1234) and a severity score (CVSS).
#
# PYTHON CONCEPTS COVERED:
# - Making HTTP requests with the httpx library
# - Working with JSON data (nested dictionaries)
# - try/except error handling
# - for loops to process lists of items
# - The datetime module for working with dates
# ============================================================

# "httpx" is an HTTP client library that lets us make web
# requests (similar to what your browser does when you visit
# a website, but from Python code).
import httpx

# "datetime" is a built-in Python module for working with
# dates and times. We use it to fetch CVEs from a recent
# time window (e.g., last 7 days).
from datetime import datetime, timedelta, timezone

# Import our configuration constants (URLs, timeouts, etc.)
from app.config import NVD_API_URL, EPSS_API_URL, HTTP_TIMEOUT_SECONDS, NVD_RESULTS_PER_PAGE

# Import our database connection helper
from app.database import get_connection


def fetch_and_store_cves():
    """
    Fetch recent CVEs from the NVD API and save them to the database.

    HOW THIS FUNCTION WORKS (step by step):
    ----------------------------------------
    1. Calculate a date range (last 7 days)
    2. Send an HTTP GET request to the NVD API
    3. Parse the JSON response to extract CVE records
    4. For each CVE, extract the fields we care about
    5. Insert each CVE into our SQLite database
    6. Return the number of CVEs that were saved

    Returns:
        int: The number of CVE records saved to the database.
    """

    # ----------------------------------------------------------
    # STEP 1: Calculate the date range
    # ----------------------------------------------------------
    # We want CVEs published in the last 7 days.
    # datetime.now(timezone.utc) gives us the current date/time in UTC.
    # timedelta(days=7) represents a duration of 7 days.
    # Subtracting a timedelta from a datetime gives us a date in the past.
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    # The NVD API expects dates in ISO 8601 format.
    # .isoformat() converts a datetime to a string like:
    #   "2024-01-15T10:30:00+00:00"
    start_date = seven_days_ago.isoformat()
    end_date = now.isoformat()

    # ----------------------------------------------------------
    # STEP 2: Build the API request parameters
    # ----------------------------------------------------------
    # HTTP requests can include "parameters" — extra info
    # appended to the URL that tells the API what data we want.
    # For example: ?pubStartDate=2024-01-01&resultsPerPage=20
    #
    # In Python, we pass parameters as a dictionary.
    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "resultsPerPage": NVD_RESULTS_PER_PAGE,
    }

    # ----------------------------------------------------------
    # STEP 3: Make the HTTP request inside a try/except block
    # ----------------------------------------------------------
    # PYTHON CONCEPT — try/except:
    #   Code inside "try" runs normally. If ANY error occurs,
    #   Python jumps to the "except" block instead of crashing.
    #   This is called "error handling" or "exception handling".
    #
    #   Common errors when making web requests:
    #   - The website is down (ConnectionError)
    #   - The request takes too long (TimeoutError)
    #   - The API returns invalid data (ValueError)
    try:
        # httpx.get() sends an HTTP GET request to the URL.
        # This is the same thing your browser does when you
        # type a URL into the address bar!
        #
        # "timeout" sets how many seconds to wait for a response.
        # If the server doesn't respond in time, httpx raises
        # a TimeoutException.
        response = httpx.get(
            NVD_API_URL,
            params=params,
            timeout=HTTP_TIMEOUT_SECONDS,
        )

        # .raise_for_status() checks if the server returned an
        # error code (like 404 Not Found or 500 Server Error).
        # If so, it raises an exception that our "except" block
        # will catch.
        response.raise_for_status()

        # .json() converts the response body from a JSON string
        # into a Python dictionary. JSON is a text format that
        # looks very similar to Python dictionaries:
        #   {"key": "value", "numbers": [1, 2, 3]}
        data = response.json()

    except Exception as error:
        # If ANYTHING goes wrong (network error, timeout, bad
        # response), we print an error message and return 0
        # to indicate no records were saved.
        #
        # "f-strings" (f"...") let us embed variables inside
        # strings using curly braces {variable_name}.
        print(f"❌ Error fetching CVEs from NVD: {error}")
        return 0

    # ----------------------------------------------------------
    # STEP 4: Extract CVE records from the response
    # ----------------------------------------------------------
    # The NVD API returns a nested JSON structure. The key
    # "vulnerabilities" contains a list of CVE objects.
    #
    # PYTHON CONCEPT — .get() method:
    #   dictionary.get("key", default_value)
    #   This safely retrieves a value from a dictionary.
    #   If the key doesn't exist, it returns the default_value
    #   instead of crashing with a KeyError.
    #
    #   Compare:
    #     data["vulnerabilities"]     → crashes if key missing
    #     data.get("vulnerabilities", [])  → returns [] if missing
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        print("ℹ️  No new CVEs found in the last 7 days.")
        return 0

    # ----------------------------------------------------------
    # STEP 5: Process each CVE and insert into the database
    # ----------------------------------------------------------
    saved_count = 0

    # Open a database connection. The "with" statement ensures
    # the connection is properly closed when we're done.
    with get_connection() as conn:
        cursor = conn.cursor()

        # PYTHON CONCEPT — for loop:
        #   "for item in list" iterates over each element in
        #   the list, one at a time. The variable "item" takes
        #   on the value of each element in turn.
        for item in vulnerabilities:
            # The NVD API nests the actual CVE data inside
            # a "cve" key within each vulnerability object.
            cve = item.get("cve", {})

            # Extract the CVE ID (e.g., "CVE-2024-1234")
            cve_id = cve.get("id", "")

            # Skip this record if it has no ID (bad data)
            if not cve_id:
                continue

            # Extract the English description.
            # The descriptions are in a list of dictionaries,
            # each with a "lang" key and a "value" key.
            # We look for the English ("en") description.
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    # "break" exits the for loop early because
                    # we found what we were looking for.
                    break

            # Extract CVSS severity and score.
            # The NVD API puts metrics inside nested dictionaries.
            # We have to carefully navigate the structure.
            severity = "UNKNOWN"
            cvss_score = None
            metrics = cve.get("metrics", {})

            # Try CVSS v3.1 first (most common), then v3.0
            for version_key in ["cvssMetricV31", "cvssMetricV30"]:
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    # metric_list is a list; we want the first item
                    cvss_data = metric_list[0].get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    cvss_score = cvss_data.get("baseScore")
                    break

            # Extract dates
            published_date = cve.get("published", "")
            last_modified = cve.get("lastModified", "")

            # -----------------------------------------------
            # STEP 5b: Insert into the database
            # -----------------------------------------------
            # SQL INSERT OR IGNORE means:
            #   - Insert this row into the table.
            #   - If a row with the same cve_id already exists
            #     (because cve_id is UNIQUE), silently skip it.
            #
            # The "?" placeholders are filled in by the tuple
            # of values. This is called "parameterized queries"
            # and it PREVENTS SQL injection attacks!
            #
            # SECURITY CONCEPT — SQL Injection:
            #   NEVER put user/external data directly into SQL:
            #     cursor.execute(f"INSERT ... VALUES ('{cve_id}')")  # DANGEROUS!
            #   ALWAYS use ? placeholders:
            #     cursor.execute("INSERT ... VALUES (?)", (cve_id,))  # SAFE!
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO cves
                    (cve_id, description, severity, cvss_score, published_date, last_modified)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (cve_id, description, severity, cvss_score, published_date, last_modified))

                # cursor.rowcount tells us how many rows were affected.
                # If the CVE already existed, rowcount will be 0 (ignored).
                if cursor.rowcount > 0:
                    saved_count += 1

            except Exception as db_error:
                print(f"⚠️  Error saving CVE {cve_id}: {db_error}")

        # Save all the inserts to the database file.
        conn.commit()

        # Update the fetch_log table to record when we last fetched
        cursor.execute("""
            INSERT OR REPLACE INTO fetch_log (source_name, last_fetch, status, record_count)
            VALUES (?, datetime('now'), 'success', ?)
        """, ("nvd_cves", saved_count))
        conn.commit()

    print(f"✅ Saved {saved_count} new CVEs to the database.")
    return saved_count


def fetch_epss_scores():
    """
    Fetch EPSS exploit probability scores and update existing CVEs.

    EPSS (Exploit Prediction Scoring System) tells us how likely
    a vulnerability is to be exploited in the next 30 days.
    A score of 0.97 means 97% probability of exploitation!

    This function:
    1. Gets all CVE IDs from our database
    2. Sends them to the EPSS API in a batch
    3. Updates each CVE's epss_score in our database
    """
    # First, get all CVE IDs currently in our database
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT cve_id FROM cves WHERE epss_score IS NULL LIMIT 30")
        rows = cursor.fetchall()

    # If there are no CVEs to update, exit early
    if not rows:
        return 0

    # Build a comma-separated string of CVE IDs for the API
    # PYTHON CONCEPT — List Comprehension:
    #   [row["cve_id"] for row in rows]
    #   This creates a new list by extracting the "cve_id"
    #   value from each row. It's a shortcut for:
    #     cve_ids = []
    #     for row in rows:
    #         cve_ids.append(row["cve_id"])
    cve_ids = [row["cve_id"] for row in rows]
    cve_string = ",".join(cve_ids)

    try:
        response = httpx.get(
            EPSS_API_URL,
            params={"cve": cve_string},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()

    except Exception as error:
        print(f"❌ Error fetching EPSS scores: {error}")
        return 0

    # Update each CVE with its EPSS score
    updated = 0
    epss_data = data.get("data", [])

    with get_connection() as conn:
        cursor = conn.cursor()
        for entry in epss_data:
            cve_id = entry.get("cve", "")
            epss_score = entry.get("epss")

            if cve_id and epss_score is not None:
                try:
                    # float() converts a string like "0.97" to the
                    # number 0.97. This is called "type casting".
                    cursor.execute(
                        "UPDATE cves SET epss_score = ? WHERE cve_id = ?",
                        (float(epss_score), cve_id),
                    )
                    if cursor.rowcount > 0:
                        updated += 1
                except Exception as db_error:
                    print(f"⚠️  Error updating EPSS for {cve_id}: {db_error}")

        conn.commit()

    print(f"✅ Updated {updated} CVEs with EPSS scores.")
    return updated
