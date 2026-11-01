"""Shared refresh execution, protected by a cross-process renewable lease."""

import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from app.database import get_connection


@contextmanager
def refresh_lease():
    owner = uuid.uuid4().hex
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        now = time.time()
        conn.execute("DELETE FROM job_leases WHERE name='feed_refresh' AND expires_at <= ?", (now,))
        acquired = conn.execute("INSERT OR IGNORE INTO job_leases VALUES ('feed_refresh', ?, ?)", (owner, now + 90)).rowcount == 1
    if not acquired:
        yield False
        return
    stopped = threading.Event()

    def renew():
        while not stopped.wait(15):
            try:
                with get_connection() as conn:
                    conn.execute("UPDATE job_leases SET expires_at=? WHERE name='feed_refresh' AND owner=?", (time.time() + 90, owner))
            except Exception:
                # Do not release someone else's lease if renewal/storage failed.
                stopped.set()

    thread = threading.Thread(target=renew, name="CyberDash-RefreshLease", daemon=True)
    thread.start()
    try:
        yield True
    finally:
        stopped.set()
        thread.join(timeout=5)
        with get_connection() as conn:
            conn.execute("DELETE FROM job_leases WHERE name='feed_refresh' AND owner=?", (owner,))


def run_feed_refresh(*, scheduled=False):
    from app.services.cve_service import fetch_and_store_cves, fetch_epss_scores
    from app.services.cisa_service import fetch_and_store_cisa_kev
    from app.services.rss_service import fetch_and_store_rss
    from app.services.threat_service import fetch_all_threat_intel
    from app.services.webhook_service import notify_all_webhooks

    with refresh_lease() as acquired:
        if not acquired:
            return {"status": "busy", "message": "A feed refresh is already running."}
        if scheduled:
            # Recheck due time under the lease: another worker may have just run.
            with get_connection() as conn:
                settings = dict(conn.execute("SELECT key,value FROM app_settings").fetchall())
            next_run = settings.get("schedule_next_refresh")
            if settings.get("schedule_enabled") != "1" or not next_run or datetime.fromisoformat(next_run) > datetime.now(timezone.utc):
                return {"status": "not_due"}
        with get_connection() as conn:
            cve_head = conn.execute("SELECT COALESCE(MAX(id),0) FROM cves").fetchone()[0]
            cisa_head = conn.execute("SELECT COALESCE(MAX(id),0) FROM cisa_exploits").fetchone()[0]
        results = {"errors": []}
        for name, fetcher in (("cves_saved", fetch_and_store_cves), ("epss_updated", fetch_epss_scores),
                              ("cisa_saved", fetch_and_store_cisa_kev), ("articles_saved", fetch_and_store_rss),
                              ("threats_saved", fetch_all_threat_intel)):
            try:
                results[name] = fetcher()
            except Exception:
                results[name] = 0
                results["errors"].append(name)
        with get_connection() as conn:
            new_cves = [dict(row) for row in conn.execute("SELECT * FROM cves WHERE id > ?", (cve_head,))]
            new_cisa = [dict(row) for row in conn.execute("SELECT * FROM cisa_exploits WHERE id > ?", (cisa_head,))]
        try:
            results["notifications"] = notify_all_webhooks(
                new_critical_cves=[r for r in new_cves if r["severity"] == "CRITICAL"],
                new_high_cves=[r for r in new_cves if r["severity"] == "HIGH"], new_cisa_exploits=new_cisa)
        except Exception:
            results["errors"].append("notifications")
        results["status"] = "partial" if results["errors"] else "complete"
        if scheduled:
            now = datetime.now(timezone.utc)
            with get_connection() as conn:
                interval = conn.execute("SELECT value FROM app_settings WHERE key='schedule_interval_hours'").fetchone()
                hours = int(interval[0]) if interval else 24
                # Do not overwrite a new schedule chosen while this refresh ran.
                current = conn.execute("SELECT value FROM app_settings WHERE key='schedule_next_refresh'").fetchone()
                if current and current[0] == next_run:
                    conn.execute("INSERT OR REPLACE INTO app_settings VALUES ('schedule_next_refresh', ?)", ((now + timedelta(hours=hours)).isoformat(),))
                conn.execute("INSERT OR REPLACE INTO app_settings VALUES ('schedule_last_refresh', ?)", (now.isoformat(),))
        return results
