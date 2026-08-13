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


def _build_where_clause(base_conditions=None, start_date=None, end_date=None, date_column="fetched_at"):
    """
    Helper function to build dynamic SQL WHERE clauses and parameters safely.

    BEGINNER PYTHON CONCEPT — Helper Functions:
    --------------------------------------------
    When multiple functions need to build similar SQL queries,
    we extract that logic into a helper function to avoid
    repeating code (DRY principle: Don't Repeat Yourself).

    Args:
        base_conditions: List of (sql_snippet, param) tuples for non-date filters
        start_date: String in 'YYYY-MM-DD' format (optional)
        end_date: String in 'YYYY-MM-DD' format (optional)
        date_column: The table column containing dates

    Returns:
        tuple: (where_clause_str, params_list)
    """
    conditions = []
    params = []

    # Add non-date base conditions (e.g. severity = ?)
    if base_conditions:
        for condition_str, param_val in base_conditions:
            if condition_str:
                conditions.append(condition_str)
            if param_val is not None:
                if isinstance(param_val, (list, tuple)):
                    params.extend(param_val)
                else:
                    params.append(param_val)

    # Add start_date filter if provided
    if start_date:
        conditions.append(f"date({date_column}) >= ?")
        params.append(start_date)

    # Add end_date filter if provided
    if end_date:
        conditions.append(f"date({date_column}) <= ?")
        params.append(end_date)

    # Join all conditions with " AND "
    if conditions:
        return "WHERE " + " AND ".join(conditions), params
    return "", params


def get_recent_cves(limit=50, severity_filter=None, start_date=None, end_date=None, search_query=None):
    """
    Retrieve CVEs from the database with optional severity, date range, and keyword/CVE ID search filtering.

    Args:
        limit: Maximum number of CVEs to return.
        severity_filter: Filter by severity (CRITICAL, HIGH, etc.)
        start_date: Start date string 'YYYY-MM-DD'
        end_date: End date string 'YYYY-MM-DD'
        search_query: Search string to match CVE ID or description
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        base_conds = []
        if severity_filter:
            base_conds.append(("severity = ?", severity_filter))
        if search_query:
            pattern = f"%{search_query.strip()}%"
            base_conds.append(("(cve_id LIKE ? OR description LIKE ?)", (pattern, pattern)))

        where_str, params = _build_where_clause(
            base_conditions=base_conds,
            start_date=start_date,
            end_date=end_date,
            date_column="COALESCE(published_date, fetched_at)"
        )

        query = f"""
            SELECT * FROM cves
            {where_str}
            ORDER BY published_date DESC
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_cisa_exploits(limit=50, start_date=None, end_date=None):
    """
    Retrieve CISA Known Exploited Vulnerabilities with date filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        where_str, params = _build_where_clause(
            start_date=start_date,
            end_date=end_date,
            date_column="COALESCE(date_added, fetched_at)"
        )

        query = f"""
            SELECT * FROM cisa_exploits
            {where_str}
            ORDER BY date_added DESC
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_rss_articles(limit=50, source_filter=None, start_date=None, end_date=None):
    """
    Retrieve security news articles with source and date range filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        base_conds = [("source = ?", source_filter)] if source_filter else []
        where_str, params = _build_where_clause(
            base_conditions=base_conds,
            start_date=start_date,
            end_date=end_date,
            date_column="fetched_at"
        )

        query = f"""
            SELECT * FROM rss_articles
            {where_str}
            ORDER BY fetched_at DESC
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_threat_indicators(limit=50, indicator_type=None, start_date=None, end_date=None):
    """
    Retrieve threat indicators with type and date range filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        base_conds = [("indicator_type = ?", indicator_type)] if indicator_type else []
        where_str, params = _build_where_clause(
            base_conditions=base_conds,
            start_date=start_date,
            end_date=end_date,
            date_column="COALESCE(date_added, fetched_at)"
        )

        query = f"""
            SELECT * FROM threat_indicators
            {where_str}
            ORDER BY fetched_at DESC
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_dashboard_summary(start_date=None, end_date=None):
    """
    Get summary statistics for the dashboard header, respecting date filters.
    """
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

        # CVE counts
        cve_where, cve_params = _build_where_clause(
            start_date=start_date, end_date=end_date, date_column="COALESCE(published_date, fetched_at)"
        )
        cursor.execute(f"SELECT COUNT(*) as count FROM cves {cve_where}", tuple(cve_params))
        row = cursor.fetchone()
        summary["total_cves"] = row["count"] if row else 0

        # Critical CVEs
        crit_where, crit_params = _build_where_clause(
            base_conditions=[("severity = ?", "CRITICAL")],
            start_date=start_date, end_date=end_date, date_column="COALESCE(published_date, fetched_at)"
        )
        cursor.execute(f"SELECT COUNT(*) as count FROM cves {crit_where}", tuple(crit_params))
        row = cursor.fetchone()
        summary["critical_cves"] = row["count"] if row else 0

        # High CVEs
        high_where, high_params = _build_where_clause(
            base_conditions=[("severity = ?", "HIGH")],
            start_date=start_date, end_date=end_date, date_column="COALESCE(published_date, fetched_at)"
        )
        cursor.execute(f"SELECT COUNT(*) as count FROM cves {high_where}", tuple(high_params))
        row = cursor.fetchone()
        summary["high_cves"] = row["count"] if row else 0

        # CISA Exploits
        cisa_where, cisa_params = _build_where_clause(
            start_date=start_date, end_date=end_date, date_column="COALESCE(date_added, fetched_at)"
        )
        cursor.execute(f"SELECT COUNT(*) as count FROM cisa_exploits {cisa_where}", tuple(cisa_params))
        row = cursor.fetchone()
        summary["active_exploits"] = row["count"] if row else 0

        # RSS Articles
        rss_where, rss_params = _build_where_clause(
            start_date=start_date, end_date=end_date, date_column="fetched_at"
        )
        cursor.execute(f"SELECT COUNT(*) as count FROM rss_articles {rss_where}", tuple(rss_params))
        row = cursor.fetchone()
        summary["total_articles"] = row["count"] if row else 0

        # Threat Indicators
        threat_where, threat_params = _build_where_clause(
            start_date=start_date, end_date=end_date, date_column="COALESCE(date_added, fetched_at)"
        )
        cursor.execute(f"SELECT COUNT(*) as count FROM threat_indicators {threat_where}", tuple(threat_params))
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
