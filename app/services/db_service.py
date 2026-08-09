# ============================================================
# app/services/db_service.py — Database Query Helper Functions
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This file contains functions that READ data FROM the database.
# While the other service files (cve_service, rss_service, etc.)
# WRITE data INTO the database, this file focuses on querying
# (SELECT) data back out for display on the dashboard.
#
# WHY SEPARATE READS FROM WRITES?
# --------------------------------
# Separating "fetch & store" logic from "query & display" logic
# keeps the code organized. When we need to change how data
# is displayed, we only edit this file — we don't have to touch
# the fetcher code.
#
# PYTHON CONCEPTS COVERED:
# - SQL SELECT queries with WHERE, ORDER BY, and LIMIT
# - Converting sqlite3.Row objects to regular dictionaries
# - Functions with default parameter values
# - The "ternary operator" (inline if/else)
# ============================================================

from app.database import get_connection


def get_recent_cves(limit=20, severity_filter=None):
    """
    Retrieve recent CVEs from the database.

    PYTHON CONCEPT — Default Parameter Values:
    -------------------------------------------
    "limit=20" means if the caller doesn't specify a limit,
    it defaults to 20. Both of these calls are valid:
        get_recent_cves()          → uses limit=20
        get_recent_cves(limit=50)  → uses limit=50

    Args:
        limit: Maximum number of CVEs to return (default: 20).
        severity_filter: If provided (e.g., "CRITICAL"), only
                         return CVEs matching that severity.

    Returns:
        list: A list of dictionaries, each representing a CVE.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Build the SQL query dynamically based on whether
        # a severity filter was provided.
        #
        # PYTHON CONCEPT — Ternary Operator:
        #   value_if_true IF condition ELSE value_if_false
        #   This is a one-line shortcut for a simple if/else.
        if severity_filter:
            # When filtering by severity, we add a WHERE clause.
            # The "?" placeholder prevents SQL injection.
            cursor.execute("""
                SELECT * FROM cves
                WHERE severity = ?
                ORDER BY published_date DESC
                LIMIT ?
            """, (severity_filter, limit))
        else:
            # No filter: return all CVEs, newest first.
            # ORDER BY published_date DESC sorts in descending
            # order (newest dates first).
            # LIMIT restricts how many rows are returned.
            cursor.execute("""
                SELECT * FROM cves
                ORDER BY published_date DESC
                LIMIT ?
            """, (limit,))
            # NOTE: (limit,) has a trailing comma to make it a
            # TUPLE with one element. Without the comma, Python
            # would treat (limit) as just parentheses around
            # the variable, not as a tuple!
            #   (limit)  → same as just "limit" (an integer)
            #   (limit,) → a tuple containing one integer

        # cursor.fetchall() retrieves ALL matching rows at once.
        # Each row is a sqlite3.Row object (because we set
        # row_factory in database.py).
        rows = cursor.fetchall()

    # Convert sqlite3.Row objects to regular dictionaries.
    # PYTHON CONCEPT — dict(row):
    #   dict() can convert various objects into dictionaries.
    #   sqlite3.Row objects support this conversion because
    #   we set conn.row_factory = sqlite3.Row.
    #
    #   This is equivalent to:
    #     result = []
    #     for row in rows:
    #         result.append(dict(row))
    #     return result
    #
    #   But the list comprehension below is more concise!
    return [dict(row) for row in rows]


def get_cisa_exploits(limit=20):
    """
    Retrieve CISA Known Exploited Vulnerabilities from the database.

    These are the vulnerabilities that attackers are actively
    exploiting in the wild. They should be treated as the
    highest priority for patching.

    Args:
        limit: Maximum number of entries to return.

    Returns:
        list: A list of CISA exploit dictionaries.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM cisa_exploits
            ORDER BY date_added DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_rss_articles(limit=30, source_filter=None):
    """
    Retrieve security news articles from the database.

    Args:
        limit: Maximum number of articles to return.
        source_filter: If provided, only return articles from
                       this specific RSS feed source.

    Returns:
        list: A list of article dictionaries.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        if source_filter:
            cursor.execute("""
                SELECT * FROM rss_articles
                WHERE source = ?
                ORDER BY fetched_at DESC
                LIMIT ?
            """, (source_filter, limit))
        else:
            cursor.execute("""
                SELECT * FROM rss_articles
                ORDER BY fetched_at DESC
                LIMIT ?
            """, (limit,))

        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_threat_indicators(limit=30, indicator_type=None):
    """
    Retrieve threat indicators (malicious URLs and IPs)
    from the database.

    Args:
        limit: Maximum number of indicators to return.
        indicator_type: If provided ("url" or "ip"), filter
                        by indicator type.

    Returns:
        list: A list of threat indicator dictionaries.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        if indicator_type:
            cursor.execute("""
                SELECT * FROM threat_indicators
                WHERE indicator_type = ?
                ORDER BY fetched_at DESC
                LIMIT ?
            """, (indicator_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM threat_indicators
                ORDER BY fetched_at DESC
                LIMIT ?
            """, (limit,))

        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_dashboard_summary():
    """
    Get summary statistics for the dashboard header.

    This function runs several COUNT queries to give us
    quick statistics like "how many total CVEs" and
    "how many are CRITICAL".

    SQL CONCEPT — COUNT():
    ----------------------
    COUNT(*) counts the total number of rows in a table.
    COUNT(*) with WHERE counts only rows matching a condition:
        SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'

    Returns:
        dict: A dictionary of summary statistics.
    """
    # We create a dictionary to hold all our summary stats.
    # We'll fill it in one query at a time.
    summary = {
        "total_cves": 0,
        "critical_cves": 0,
        "high_cves": 0,
        "active_exploits": 0,
        "total_articles": 0,
        "total_threats": 0,
    }

    with get_connection() as conn:
        cursor = conn.cursor()

        # Count total CVEs
        cursor.execute("SELECT COUNT(*) as count FROM cves")
        # cursor.fetchone() retrieves just ONE row (the count).
        # We access the "count" column to get the number.
        row = cursor.fetchone()
        summary["total_cves"] = row["count"] if row else 0

        # Count CRITICAL severity CVEs
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE severity = 'CRITICAL'")
        row = cursor.fetchone()
        summary["critical_cves"] = row["count"] if row else 0

        # Count HIGH severity CVEs
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE severity = 'HIGH'")
        row = cursor.fetchone()
        summary["high_cves"] = row["count"] if row else 0

        # Count CISA active exploits
        cursor.execute("SELECT COUNT(*) as count FROM cisa_exploits")
        row = cursor.fetchone()
        summary["active_exploits"] = row["count"] if row else 0

        # Count RSS articles
        cursor.execute("SELECT COUNT(*) as count FROM rss_articles")
        row = cursor.fetchone()
        summary["total_articles"] = row["count"] if row else 0

        # Count threat indicators
        cursor.execute("SELECT COUNT(*) as count FROM threat_indicators")
        row = cursor.fetchone()
        summary["total_threats"] = row["count"] if row else 0

    return summary


def get_rss_sources():
    """
    Get a list of unique RSS feed source names from the database.

    This is used to populate the source filter dropdown on the
    dashboard's news section.

    SQL CONCEPT — DISTINCT:
    -----------------------
    SELECT DISTINCT source FROM rss_articles
    Returns only unique values — if "Krebs on Security" appears
    50 times, DISTINCT returns it only once.

    Returns:
        list: A list of unique source name strings.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT source FROM rss_articles ORDER BY source")
        rows = cursor.fetchall()

    # Extract just the "source" string from each row
    return [row["source"] for row in rows]
