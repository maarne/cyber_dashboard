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
# SECURITY / PARAMETERIZATION:
# ----------------------------
# All queries use prepared statements with strict positional '?'
# parameter binding, eliminating SQL injection (CWE-89) risks.
# ============================================================

from app.database import get_connection


def get_recent_cves(limit=50, severity_filter=None, start_date=None, end_date=None, search_query=None):
    """
    Retrieve CVEs from the database with optional severity, date range, and keyword/CVE ID search filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        search_pattern = f"%{search_query.strip()}%" if search_query else None

        query = """
            SELECT * FROM cves
            WHERE (? IS NULL OR severity = ?)
              AND (? IS NULL OR cve_id LIKE ? OR description LIKE ?)
              AND (? IS NULL OR date(COALESCE(published_date, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(published_date, fetched_at)) <= ?)
            ORDER BY published_date DESC
            LIMIT ?
        """
        cursor.execute(
            query,
            (
                severity_filter,
                severity_filter,
                search_pattern,
                search_pattern,
                search_pattern,
                start_date,
                start_date,
                end_date,
                end_date,
                limit,
            ),
        )
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_cisa_exploits(limit=50, start_date=None, end_date=None):
    """
    Retrieve CISA Known Exploited Vulnerabilities with date filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT * FROM cisa_exploits
            WHERE (? IS NULL OR date(COALESCE(date_added, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(date_added, fetched_at)) <= ?)
            ORDER BY date_added DESC
            LIMIT ?
        """
        cursor.execute(query, (start_date, start_date, end_date, end_date, limit))
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_rss_articles(limit=50, source_filter=None, start_date=None, end_date=None):
    """
    Retrieve security news articles with source and date range filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT * FROM rss_articles
            WHERE (? IS NULL OR source = ?)
              AND (? IS NULL OR date(fetched_at) >= ?)
              AND (? IS NULL OR date(fetched_at) <= ?)
            ORDER BY fetched_at DESC
            LIMIT ?
        """
        cursor.execute(
            query,
            (source_filter, source_filter, start_date, start_date, end_date, end_date, limit),
        )
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_threat_indicators(limit=50, indicator_type=None, start_date=None, end_date=None):
    """
    Retrieve threat indicators with type and date range filtering.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT * FROM threat_indicators
            WHERE (? IS NULL OR indicator_type = ?)
              AND (? IS NULL OR date(COALESCE(date_added, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(date_added, fetched_at)) <= ?)
            ORDER BY fetched_at DESC
            LIMIT ?
        """
        cursor.execute(
            query,
            (indicator_type, indicator_type, start_date, start_date, end_date, end_date, limit),
        )
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
        cve_query = """
            SELECT COUNT(*) as count FROM cves
            WHERE (? IS NULL OR date(COALESCE(published_date, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(published_date, fetched_at)) <= ?)
        """
        cursor.execute(cve_query, (start_date, start_date, end_date, end_date))
        row = cursor.fetchone()
        summary["total_cves"] = row["count"] if row else 0

        # Critical CVEs
        crit_query = """
            SELECT COUNT(*) as count FROM cves
            WHERE severity = 'CRITICAL'
              AND (? IS NULL OR date(COALESCE(published_date, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(published_date, fetched_at)) <= ?)
        """
        cursor.execute(crit_query, (start_date, start_date, end_date, end_date))
        row = cursor.fetchone()
        summary["critical_cves"] = row["count"] if row else 0

        # High CVEs
        high_query = """
            SELECT COUNT(*) as count FROM cves
            WHERE severity = 'HIGH'
              AND (? IS NULL OR date(COALESCE(published_date, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(published_date, fetched_at)) <= ?)
        """
        cursor.execute(high_query, (start_date, start_date, end_date, end_date))
        row = cursor.fetchone()
        summary["high_cves"] = row["count"] if row else 0

        # CISA Exploits
        cisa_query = """
            SELECT COUNT(*) as count FROM cisa_exploits
            WHERE (? IS NULL OR date(COALESCE(date_added, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(date_added, fetched_at)) <= ?)
        """
        cursor.execute(cisa_query, (start_date, start_date, end_date, end_date))
        row = cursor.fetchone()
        summary["active_exploits"] = row["count"] if row else 0

        # RSS Articles
        rss_query = """
            SELECT COUNT(*) as count FROM rss_articles
            WHERE (? IS NULL OR date(fetched_at) >= ?)
              AND (? IS NULL OR date(fetched_at) <= ?)
        """
        cursor.execute(rss_query, (start_date, start_date, end_date, end_date))
        row = cursor.fetchone()
        summary["total_articles"] = row["count"] if row else 0

        # Threat Indicators
        threat_query = """
            SELECT COUNT(*) as count FROM threat_indicators
            WHERE (? IS NULL OR date(COALESCE(date_added, fetched_at)) >= ?)
              AND (? IS NULL OR date(COALESCE(date_added, fetched_at)) <= ?)
        """
        cursor.execute(threat_query, (start_date, start_date, end_date, end_date))
        row = cursor.fetchone()
        summary["total_threats"] = row["count"] if row else 0

    return summary


def get_rss_sources():
    """
    Get a list of unique RSS feed source names from the database.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT source FROM rss_articles ORDER BY source")
        rows = cursor.fetchall()

    return [row["source"] for row in rows if row["source"]]
