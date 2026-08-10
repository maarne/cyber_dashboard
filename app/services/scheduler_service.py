# ============================================================
# app/services/scheduler_service.py — Background Feed Scheduler
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This file manages a background scheduler that automatically
# refreshes all data feeds (CVEs, CISA, RSS, Threats) at a
# user-configured interval (e.g., every 6, 12, 24, or 48 hours).
#
# WHAT IS A "BACKGROUND THREAD"?
# ------------------------------
# By default, Python runs code line-by-line in a single
# "thread" (like a single lane on a highway). A background
# thread is a second lane that runs code simultaneously.
#
# We use a background thread so the scheduler can sleep for
# hours between refreshes WITHOUT blocking the web server
# from handling user requests.
#
# PYTHON CONCEPTS COVERED:
# - threading.Thread: Running code in the background
# - threading.Event: A signal to wake up or stop a thread
# - daemon threads: Threads that stop when the main program stops
# - Global state management with module-level variables
# - The datetime module for timestamps
# ============================================================

# threading is a built-in Python module for running code
# concurrently (at the same time) in separate threads.
import threading

# datetime lets us work with dates and times.
from datetime import datetime, timezone

# We'll import the database helpers to store/retrieve settings
# and the refresh logic to call during scheduled runs.
from app.database import get_connection


# ============================================================
# MODULE-LEVEL STATE
# ============================================================
# These variables live at the module level (outside any
# function), which means they persist for the lifetime of the
# application. All functions in this file share them.
#
# PYTHON CONCEPT — Module-Level Variables:
#   Variables defined at the top of a .py file (outside any
#   class or function) are called "module-level" or "global"
#   variables. They are created once when the module is first
#   imported, and they persist until the program ends.
# ============================================================

# The background thread object (or None if no scheduler is running).
_scheduler_thread = None

# A threading.Event is like a flag that threads can check.
# - _stop_event.set()   → raises the flag (signals "stop!")
# - _stop_event.wait(n) → waits up to n seconds, returning
#                          True immediately if the flag is raised.
# - _stop_event.clear() → lowers the flag (reset)
#
# We use this to wake the sleeping thread when the user
# changes the schedule, instead of waiting for the full
# sleep interval to expire.
_stop_event = threading.Event()

# Track the last scheduled refresh timestamp (for display).
_last_scheduled_refresh = None

# Valid interval options (in hours).
VALID_INTERVALS = [6, 12, 24, 48]


# ============================================================
# DATABASE HELPERS — Schedule Settings
# ============================================================
# We store the schedule configuration in the app_settings
# table as key-value pairs. This is a simple pattern for
# storing a small number of settings.
# ============================================================


def get_schedule_settings():
    """
    Retrieve the current schedule settings from the database.

    Returns:
        dict: A dictionary with:
            - enabled (bool): Whether auto-refresh is on.
            - interval_hours (int): How often to refresh (6/12/24/48).
            - last_refresh (str or None): Timestamp of last scheduled refresh.
            - next_refresh (str or None): Estimated time of next refresh.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Ensure the table exists (safe to call repeatedly)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.commit()

        # Fetch all settings into a dictionary
        cursor.execute("SELECT key, value FROM app_settings")
        rows = cursor.fetchall()
        settings_map = {row["key"]: row["value"] for row in rows}

    # Build the response with defaults if keys are missing.
    # .get(key, default) returns the default if the key isn't found.
    enabled = settings_map.get("schedule_enabled", "0") == "1"
    interval_hours = int(settings_map.get("schedule_interval_hours", "24"))
    last_refresh = settings_map.get("schedule_last_refresh", None)

    # Calculate the estimated next refresh time.
    next_refresh = None
    if enabled and last_refresh:
        try:
            from datetime import timedelta
            last_dt = datetime.fromisoformat(last_refresh)
            next_dt = last_dt + timedelta(hours=interval_hours)
            next_refresh = next_dt.isoformat()
        except (ValueError, TypeError):
            pass

    return {
        "enabled": enabled,
        "interval_hours": interval_hours,
        "last_refresh": last_refresh,
        "next_refresh": next_refresh,
    }


def save_schedule_settings(enabled, interval_hours):
    """
    Save the schedule settings to the database.

    SQL CONCEPT — INSERT OR REPLACE:
        This is a shortcut that says:
        - If a row with this PRIMARY KEY already exists → UPDATE it.
        - If no row exists → INSERT a new one.
        This avoids having to write separate INSERT and UPDATE logic.

    Args:
        enabled: True to enable auto-refresh, False to disable.
        interval_hours: Refresh interval (6, 12, 24, or 48).
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Ensure the table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Save both settings using INSERT OR REPLACE.
        cursor.execute(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
            ("schedule_enabled", "1" if enabled else "0"),
        )
        cursor.execute(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
            ("schedule_interval_hours", str(interval_hours)),
        )

        conn.commit()


def _update_last_refresh_timestamp():
    """Record the current time as the last scheduled refresh."""
    global _last_scheduled_refresh
    now = datetime.now(timezone.utc).isoformat()
    _last_scheduled_refresh = now

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cursor.execute(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
            ("schedule_last_refresh", now),
        )
        conn.commit()


# ============================================================
# BACKGROUND SCHEDULER THREAD
# ============================================================
# The scheduler runs as a "daemon thread." A daemon thread
# automatically stops when the main program exits, so we
# don't have to worry about cleaning it up manually.
#
# PYTHON CONCEPT — Daemon Threads:
#   Normal threads keep the program alive even after the main
#   code finishes. Daemon threads do NOT — they are killed
#   automatically when the main thread exits. This is perfect
#   for background tasks that should only run while the server
#   is running.
# ============================================================


def _scheduler_loop():
    """
    The main loop that runs in the background thread.

    It sleeps for the configured interval, then calls the
    refresh function. The loop continues until _stop_event
    is set (which happens when the user disables the schedule
    or changes the interval).

    PYTHON CONCEPT — while not event.is_set():
        This loop keeps running as long as _stop_event has NOT
        been signaled. When someone calls _stop_event.set(),
        the loop exits on the next check.
    """
    while not _stop_event.is_set():
        # Read the current settings each iteration (in case
        # the interval was just changed).
        settings = get_schedule_settings()

        if not settings["enabled"]:
            # Schedule was disabled — exit the thread.
            print("⏹️  Scheduler: disabled, stopping thread.")
            break

        interval_hours = settings["interval_hours"]
        interval_seconds = interval_hours * 3600  # 1 hour = 3600 seconds

        print(f"⏰ Scheduler: sleeping for {interval_hours} hour(s) "
              f"({interval_seconds} seconds)...")

        # _stop_event.wait(seconds) pauses the thread for the
        # given number of seconds, BUT returns immediately if
        # _stop_event.set() is called from another thread.
        # This lets us "wake up" the scheduler instantly when
        # the user changes settings.
        #
        # Returns True if the event was set (we should stop),
        # False if the timeout expired (time to refresh).
        was_stopped = _stop_event.wait(timeout=interval_seconds)

        if was_stopped:
            # The event was set — the user changed settings or
            # disabled the schedule. Exit the loop.
            print("⏹️  Scheduler: received stop signal.")
            break

        # Time to refresh! Import the refresh logic here to
        # avoid circular imports (main.py imports us, so we
        # can't import main.py at the module level).
        print("⏰ Scheduler: starting scheduled refresh...")
        try:
            from app.services.cve_service import fetch_and_store_cves, fetch_epss_scores
            from app.services.cisa_service import fetch_and_store_cisa_kev
            from app.services.rss_service import fetch_and_store_rss
            from app.services.threat_service import fetch_all_threat_intel
            from app.services.db_service import get_dashboard_summary, get_recent_cves, get_cisa_exploits
            from app.services.webhook_service import notify_all_webhooks

            # Snapshot before counts for webhook notifications
            before_summary = get_dashboard_summary()
            before_critical = before_summary.get("critical_cves", 0)
            before_high = before_summary.get("high_cves", 0)
            before_cisa = before_summary.get("active_exploits", 0)

            # Run all fetchers
            results = {}
            for name, func in [
                ("cves_saved", fetch_and_store_cves),
                ("epss_updated", fetch_epss_scores),
                ("cisa_saved", fetch_and_store_cisa_kev),
                ("articles_saved", fetch_and_store_rss),
                ("threats_saved", fetch_all_threat_intel),
            ]:
                try:
                    results[name] = func()
                except Exception as e:
                    print(f"  ❌ Scheduler: {name} failed: {e}")
                    results[name] = 0

            # Check for new items and send notifications
            after_summary = get_dashboard_summary()
            new_critical = max(0, after_summary.get("critical_cves", 0) - before_critical)
            new_high = max(0, after_summary.get("high_cves", 0) - before_high)
            new_cisa = max(0, after_summary.get("active_exploits", 0) - before_cisa)

            new_critical_cves = get_recent_cves(limit=new_critical, severity_filter="CRITICAL") if new_critical > 0 else []
            new_high_cves = get_recent_cves(limit=new_high, severity_filter="HIGH") if new_high > 0 else []
            new_cisa_exploits = get_cisa_exploits(limit=new_cisa) if new_cisa > 0 else []

            notify_all_webhooks(
                new_critical_cves=new_critical_cves,
                new_high_cves=new_high_cves,
                new_cisa_exploits=new_cisa_exploits,
            )

            _update_last_refresh_timestamp()

            print(f"✅ Scheduler: refresh complete — {results}")

        except Exception as e:
            print(f"❌ Scheduler: refresh failed — {e}")

    print("⏹️  Scheduler thread exiting.")


# ============================================================
# PUBLIC API — Start, Stop, Restart the Scheduler
# ============================================================
# These functions are called from main.py when the user
# toggles the schedule on/off or changes the interval.
# ============================================================


def start_scheduler():
    """
    Start the background scheduler thread.

    If a scheduler is already running, it is stopped first
    to avoid duplicate threads.

    PYTHON CONCEPT — threading.Thread():
        Thread(target=func) creates a new thread that will
        run the given function. .start() begins execution.
        daemon=True marks it as a daemon thread.
    """
    global _scheduler_thread

    # Stop any existing scheduler first
    stop_scheduler()

    # Clear the stop event so the new thread can run
    _stop_event.clear()

    settings = get_schedule_settings()
    if not settings["enabled"]:
        print("⏹️  Scheduler: not starting (disabled in settings).")
        return

    # Create and start a new daemon thread
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        name="CyberDash-Scheduler",
        daemon=True,  # Stops when main program exits
    )
    _scheduler_thread.start()
    print(f"⏰ Scheduler: started (every {settings['interval_hours']} hours)")


def stop_scheduler():
    """
    Stop the currently running scheduler thread (if any).

    We signal the thread to stop by setting the _stop_event,
    then wait briefly for it to finish.

    PYTHON CONCEPT — thread.join(timeout):
        .join() waits for a thread to finish. The timeout
        parameter sets a maximum wait time (in seconds).
        Without a timeout, .join() would block forever if
        the thread never stops.
    """
    global _scheduler_thread

    if _scheduler_thread and _scheduler_thread.is_alive():
        print("⏹️  Scheduler: sending stop signal...")
        _stop_event.set()  # Signal the thread to stop
        _scheduler_thread.join(timeout=5)  # Wait up to 5 seconds
        _scheduler_thread = None
        print("⏹️  Scheduler: stopped.")


def restart_scheduler():
    """
    Restart the scheduler with the current settings.

    This is called when the user changes the interval or
    toggles the schedule on/off. It stops the old thread
    and starts a new one with the updated settings.
    """
    stop_scheduler()
    start_scheduler()


def get_scheduler_status():
    """
    Get the current status of the scheduler for the UI.

    Returns:
        dict: Status information including whether the thread
              is alive and the current settings.
    """
    settings = get_schedule_settings()
    is_running = _scheduler_thread is not None and _scheduler_thread.is_alive()

    return {
        "enabled": settings["enabled"],
        "interval_hours": settings["interval_hours"],
        "is_running": is_running,
        "last_refresh": settings["last_refresh"],
        "next_refresh": settings["next_refresh"],
    }
