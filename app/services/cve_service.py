"""Incremental NVD ingestion and periodically refreshed FIRST EPSS scores."""

import time
from datetime import datetime, timedelta, timezone

import httpx

from app.config import NVD_API_URL, EPSS_API_URL, HTTP_TIMEOUT_SECONDS, NVD_RESULTS_PER_PAGE
from app.database import get_connection


def fetch_json(url, *, params=None, headers=None):
    """Retry transient upstream failures without unbounded sleeps."""
    for attempt in range(4):
        response = httpx.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
        if response.status_code in (429, 502, 503, 504) and attempt < 3:
            try:
                delay = min(60, max(1, int(response.headers.get("Retry-After", 2 ** attempt))))
            except ValueError:
                delay = 2 ** attempt
            time.sleep(delay)
            continue
        response.raise_for_status()
        return response.json()
    raise RuntimeError("Upstream retry limit exceeded.")


def record_fetch(source, count, status="success"):
    with get_connection() as conn:
        conn.execute("""INSERT INTO fetch_log(source_name, last_fetch, status, record_count)
            VALUES (?, datetime('now'), ?, ?) ON CONFLICT(source_name) DO UPDATE SET
            last_fetch=excluded.last_fetch, status=excluded.status, record_count=excluded.record_count""",
                     (source, status, count))


def fetch_and_store_cves():
    """Page through modified CVEs and only advance the watermark on full success."""
    import os
    now = datetime.now(timezone.utc)
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key='nvd_last_sync'").fetchone()
    start = datetime.fromisoformat(row[0]) - timedelta(minutes=5) if row else now - timedelta(days=7)
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
    saved = 0
    first_request = True
    try:
        # NVD limits a modification-time window to 120 days.
        while start < now:
            end = min(now, start + timedelta(days=120))
            index = 0
            while True:
                if not first_request:
                    time.sleep(0.7 if headers else 6.1)
                first_request = False
                data = fetch_json(NVD_API_URL, headers=headers, params={
                    "lastModStartDate": start.isoformat(), "lastModEndDate": end.isoformat(),
                    "resultsPerPage": NVD_RESULTS_PER_PAGE, "startIndex": index,
                })
                items = data.get("vulnerabilities", [])
                total = int(data.get("totalResults", len(items)))
                if not items and index < total:
                    raise ValueError("NVD returned an incomplete page.")
                with get_connection() as conn:
                    for item in items:
                        cve = item.get("cve", {})
                        cve_id = cve.get("id")
                        if not cve_id:
                            continue
                        description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                        severity, score = "UNKNOWN", None
                        for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            metrics = cve.get("metrics", {}).get(version, [])
                            if metrics:
                                metric = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
                                cvss = metric.get("cvssData", {})
                                severity = cvss.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
                                score = cvss.get("baseScore")
                                break
                        exists = conn.execute("SELECT 1 FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
                        conn.execute("""INSERT INTO cves(cve_id, description, severity, cvss_score, published_date, last_modified)
                            VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(cve_id) DO UPDATE SET
                            description=excluded.description, severity=excluded.severity, cvss_score=excluded.cvss_score,
                            published_date=excluded.published_date, last_modified=excluded.last_modified, fetched_at=datetime('now')""",
                                     (cve_id, description, severity, score, cve.get("published"), cve.get("lastModified")))
                        saved += int(not exists)
                index += len(items)
                if index >= total:
                    break
            start = end
        with get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO app_settings VALUES ('nvd_last_sync', ?)", (now.isoformat(),))
        record_fetch("nvd_cves", saved)
        return saved
    except Exception:
        record_fetch("nvd_cves", saved, "failed")
        raise


def fetch_epss_scores():
    """Refresh every stored CVE in bounded batches; EPSS is a daily changing score."""
    with get_connection() as conn:
        cve_ids = [r[0] for r in conn.execute("SELECT cve_id FROM cves ORDER BY cve_id")]
    updated = 0
    try:
        for start in range(0, len(cve_ids), 100):
            data = fetch_json(EPSS_API_URL, params={"cve": ",".join(cve_ids[start:start + 100]), "limit": 100})
            with get_connection() as conn:
                for entry in data.get("data", []):
                    score = float(entry["epss"])
                    if not 0 <= score <= 1:
                        raise ValueError("Invalid EPSS score.")
                    updated += conn.execute("UPDATE cves SET epss_score=? WHERE cve_id=?", (score, entry["cve"])).rowcount
        record_fetch("epss", updated)
        return updated
    except Exception:
        record_fetch("epss", updated, "failed")
        raise
