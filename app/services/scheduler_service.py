"""Workers poll shared schedule state; only one renewable refresh lease can run."""

import threading
from datetime import datetime, timedelta, timezone

from app.database import get_connection

VALID_INTERVALS = [6, 12, 24, 48]
_scheduler_thread = None
_stop_event = threading.Event()
_thread_lock = threading.Lock()


def get_schedule_settings():
    with get_connection() as conn:
        settings = dict(conn.execute("SELECT key, value FROM app_settings").fetchall())
    enabled = settings.get("schedule_enabled", "0") == "1"
    interval = int(settings.get("schedule_interval_hours", "24"))
    return {"enabled": enabled, "interval_hours": interval,
            "last_refresh": settings.get("schedule_last_refresh"),
            "next_refresh": settings.get("schedule_next_refresh") if enabled else None}


def save_schedule_settings(enabled, interval_hours):
    if not isinstance(enabled, bool) or interval_hours not in VALID_INTERVALS:
        raise ValueError("Invalid schedule settings.")
    next_run = (datetime.now(timezone.utc) + timedelta(hours=interval_hours)).isoformat() if enabled else ""
    with get_connection() as conn:
        conn.executemany("INSERT OR REPLACE INTO app_settings VALUES (?, ?)", [
            ("schedule_enabled", "1" if enabled else "0"),
            ("schedule_interval_hours", str(interval_hours)), ("schedule_next_refresh", next_run)])


def _scheduler_loop():
    from app.services.refresh_service import run_feed_refresh
    while not _stop_event.is_set():
        try:
            settings = get_schedule_settings()
            now = datetime.now(timezone.utc)
            with get_connection() as conn:
                conn.execute("INSERT OR REPLACE INTO app_settings VALUES ('schedule_heartbeat', ?)", (now.isoformat(),))
            if settings["enabled"]:
                if not settings["next_refresh"]:
                    # Upgrade an old schedule once, shared across workers.
                    with get_connection() as conn:
                        conn.execute("INSERT OR IGNORE INTO app_settings VALUES ('schedule_next_refresh', ?)",
                                     ((now + timedelta(hours=settings["interval_hours"])).isoformat(),))
                elif datetime.fromisoformat(settings["next_refresh"]) <= now:
                    run_feed_refresh(scheduled=True)
        except Exception as exc:
            print(f"Scheduler iteration failed ({type(exc).__name__}).")
        _stop_event.wait(5)


def start_scheduler():
    global _scheduler_thread
    with _thread_lock:
        if _scheduler_thread and _scheduler_thread.is_alive():
            return
        _stop_event.clear()
        _scheduler_thread = threading.Thread(target=_scheduler_loop, name="CyberDash-Scheduler", daemon=True)
        _scheduler_thread.start()


def stop_scheduler():
    global _scheduler_thread
    with _thread_lock:
        _stop_event.set()
        if _scheduler_thread:
            _scheduler_thread.join(timeout=5)
            # Retain the handle while work finishes. Never clear the stop flag
            # and start a second thread while the original is still running.
            if not _scheduler_thread.is_alive():
                _scheduler_thread = None


def restart_scheduler():
    # No local restart is needed: all workers see new settings within 5 seconds.
    start_scheduler()


def get_scheduler_status():
    settings = get_schedule_settings()
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key='schedule_heartbeat'").fetchone()
    recent = bool(row and datetime.now(timezone.utc) - datetime.fromisoformat(row[0]) < timedelta(seconds=30))
    return {**settings, "is_running": settings["enabled"] and recent}
