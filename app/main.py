# ============================================================
# app/main.py — FastAPI Application Entry Point
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This is the main file that starts the entire web application.
# It defines the FastAPI "app" object, sets up routes (URLs),
# and connects the backend services to the frontend templates.
#
# WHAT IS A "ROUTE"?
# ------------------
# A route is a URL pattern that the server responds to.
# When someone visits "http://localhost:8000/" in their browser,
# FastAPI finds the route matching "/" and runs its function.
#
# WHAT IS FastAPI?
# ----------------
# FastAPI is a modern Python web framework for building APIs
# and web applications. Key features:
#   - Automatic interactive API docs at /docs
#   - Built-in data validation with Pydantic
#   - High performance (one of the fastest Python frameworks)
#   - Type hints for better IDE support and error checking
#
# PYTHON CONCEPTS COVERED:
# - Decorators (@app.get, @app.post)
# - Function return values
# - Importing from your own modules
# - Running a module as a script (__name__ == "__main__")
# ============================================================

# -------------------------------------------------------
# IMPORTS
# -------------------------------------------------------
# FastAPI is the web framework class. We create one instance
# of it, and that instance IS our web application.
from fastapi import FastAPI, Request, Response, Cookie, Depends, HTTPException, status
from pydantic import BaseModel

# StaticFiles lets us serve CSS, JS, and image files.
# Jinja2Templates lets us render HTML templates with data.
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# JSONResponse lets us return JSON data from API endpoints.
from fastapi.responses import JSONResponse

# Import auth service
from app.services.auth_service import (
    verify_password,
    create_access_token,
    verify_access_token,
    get_user_by_username,
    update_user_password,
)

# Import our own modules (from the app/ package)
from app.config import APP_DIR
from app.database import initialize_database

# Import the data fetcher services
from app.services.cve_service import fetch_and_store_cves, fetch_epss_scores
from app.services.cisa_service import fetch_and_store_cisa_kev
from app.services.rss_service import (
    fetch_and_store_rss,
    get_all_rss_feeds,
    add_rss_feed,
    delete_rss_feed,
    toggle_rss_feed,
)
from app.services.threat_service import fetch_all_threat_intel

# Import the database query service
from app.services.db_service import (
    get_recent_cves,
    get_cisa_exploits,
    get_rss_articles,
    get_threat_indicators,
    get_dashboard_summary,
    get_rss_sources,
)

# Import the webhook notification service.
# This module handles sending alerts to Slack, Discord,
# Teams, or generic webhook endpoints.
from app.services.webhook_service import (
    get_all_webhooks,
    get_webhook_by_id,
    save_webhook,
    update_webhook,
    delete_webhook,
    toggle_webhook,
    notify_all_webhooks,
    send_test_notification,
)

# Import the WebhookSchema Pydantic model for validating
# webhook form data sent from the Settings page.
from app.models.schemas import WebhookSchema

# Import the background scheduler service.
# This module manages a daemon thread that automatically
# refreshes all feeds at a user-configured interval.
from app.services.scheduler_service import (
    start_scheduler,
    restart_scheduler,
    get_scheduler_status,
    get_schedule_settings,
    save_schedule_settings,
)

# Import threat actor intelligence service
from app.services.threat_actor_service import (
    get_all_threat_actors,
    get_threat_actor_by_id,
)


# ============================================================
# CREATE THE FastAPI APPLICATION
# ============================================================
# This creates the main application object. Everything in our
# web app (routes, middleware, static files) is attached to this.
#
# PYTHON CONCEPT — Keyword Arguments:
#   FastAPI(title="...", description="...", version="...")
#   These are "keyword arguments" — they let us specify which
#   parameter we're setting by NAME instead of by position.
#   This makes the code more readable.
# ============================================================
app = FastAPI(
    title="CyberDash — Cyber Security Dashboard",
    description="A Python-based dashboard aggregating CVEs, exploits, news, and threat intel.",
    version="1.0.0",
)


# ============================================================
# AUTHENTICATION MODELS & DEPENDENCIES
# ============================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

def get_current_user_optional(request: Request) -> str | None:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    if token:
        return verify_access_token(token)
    return None

def require_admin(current_user: str = Depends(get_current_user_optional)) -> str:
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in as an administrator.",
        )
    return current_user


# ============================================================
# MOUNT STATIC FILES
# ============================================================
# "Mounting" static files tells FastAPI: "When the browser
# requests any URL starting with /static/, serve the file
# from the app/static/ directory."
#
# For example:
#   Browser requests: /static/css/style.css
#   FastAPI serves:   app/static/css/style.css
# ============================================================
app.mount(
    "/static",
    StaticFiles(directory=str(APP_DIR / "static")),
    name="static",
)


# ============================================================
# SET UP JINJA2 TEMPLATES
# ============================================================
# Jinja2Templates tells FastAPI where our HTML template files
# are located. When we call templates.TemplateResponse(...),
# FastAPI will look in this directory for the template file.
# ============================================================
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


# ============================================================
# STARTUP EVENT — Runs when the server first starts
# ============================================================
# The @app.on_event("startup") decorator marks this function
# to run ONCE when the server boots up. We use it to:
# 1. Create the database tables (if they don't exist)
# 2. Print a welcome message
#
# PYTHON CONCEPT — Decorators:
#   A decorator is a special function that wraps another
#   function to add extra behavior. The "@" syntax is
#   shorthand for applying the decorator.
#
#   @app.on_event("startup")
#   def my_function():
#       ...
#
#   is equivalent to:
#   def my_function():
#       ...
#   my_function = app.on_event("startup")(my_function)
# ============================================================

@app.on_event("startup")
def on_startup():
    """
    Initialize the database when the server starts.
    This creates all tables if they don't exist yet.
    """
    print("🚀 Starting CyberDash — Cyber Security Dashboard")
    print("=" * 50)
    initialize_database()
    print("=" * 50)
    print("🌐 Dashboard available at: http://127.0.0.1:8000")
    print("📚 API documentation at:   http://127.0.0.1:8000/docs")
    print("=" * 50)

    # Start the background scheduler if it was previously enabled.
    # This means the schedule survives server restarts — if a user
    # set a 24-hour refresh schedule, it will resume automatically.
    start_scheduler()


# ============================================================
# ROUTE: Home Page (GET /)
# ============================================================
# This is the main dashboard page. When a user visits
# http://localhost:8000/ in their browser, this function runs.
#
# PYTHON CONCEPT — @app.get() Decorator:
#   @app.get("/") tells FastAPI: "When someone sends an HTTP
#   GET request to the URL '/', run this function and send
#   back whatever it returns."
#
#   GET is the HTTP method browsers use when you type a URL
#   into the address bar or click a link.
# ============================================================

@app.get("/")
def dashboard_home(request: Request, start_date: str = None, end_date: str = None, search: str = None, q: str = None):
    """
    Render the main dashboard page with data filtered by optional date range or search query.
    """
    search_query = (search or q or "").strip()
    summary = get_dashboard_summary(start_date=start_date, end_date=end_date)
    cve_limit = 100 if search_query else 50
    cves = get_recent_cves(limit=cve_limit, start_date=start_date, end_date=end_date, search_query=search_query)
    cisa_exploits = get_cisa_exploits(limit=50, start_date=start_date, end_date=end_date)
    articles = get_rss_articles(limit=50, start_date=start_date, end_date=end_date)
    threats = get_threat_indicators(limit=50, start_date=start_date, end_date=end_date)
    rss_sources = get_rss_sources()
    current_user = get_current_user_optional(request)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "summary": summary,
            "cves": cves,
            "cisa_exploits": cisa_exploits,
            "articles": articles,
            "threats": threats,
            "rss_sources": rss_sources,
            "start_date": start_date or "",
            "end_date": end_date or "",
            "search_query": search_query,
            "is_authenticated": current_user is not None,
            "current_user": current_user or "",
        },
    )


# ============================================================
# API ROUTE: Refresh All Feeds (POST /api/refresh)
# ============================================================
# AUTHENTICATION API ENDPOINTS
# ============================================================

@app.post("/api/auth/login")
def api_login(credentials: LoginRequest):
    user = get_user_by_username(credentials.username.strip())
    if not user or not verify_password(credentials.password, user["password_hash"]):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"status": "error", "message": "Invalid username or password"},
        )
    token = create_access_token(user["username"])
    res = JSONResponse(content={"status": "success", "username": user["username"]})
    res.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400,
    )
    return res


@app.post("/api/auth/logout")
def api_logout():
    res = JSONResponse(content={"status": "success", "message": "Logged out successfully"})
    res.delete_cookie("access_token")
    return res


@app.get("/api/auth/me")
def api_get_current_user_info(request: Request):
    user = get_current_user_optional(request)
    return {
        "is_authenticated": user is not None,
        "username": user or "",
    }


@app.post("/api/auth/change-password")
def api_change_password(req: ChangePasswordRequest, current_user: str = Depends(require_admin)):
    user = get_user_by_username(current_user)
    if not user or not verify_password(req.current_password, user["password_hash"]):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Current password is incorrect."},
        )
    if len(req.new_password.strip()) < 6:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "New password must be at least 6 characters long."},
        )
    update_user_password(current_user, req.new_password.strip())
    return JSONResponse(content={"message": "Password updated successfully."})


# ============================================================
# API ROUTE: Refresh All Feeds (POST /api/refresh) — Admin Only
# ============================================================
@app.post("/api/refresh")
def refresh_all_feeds(current_user: str = Depends(require_admin)):
    """
    Fetch fresh data from all external sources, store in the database,
    and send webhook notifications if new CRITICAL/HIGH CVEs or
    CISA exploits were found.

    NOTIFICATION FLOW:
    1. Snapshot the BEFORE counts (total CVEs, CISA entries)
    2. Run all fetchers (NVD, CISA, RSS, Threat Intel)
    3. Snapshot the AFTER counts
    4. If new CRITICAL/HIGH CVEs or CISA entries → notify webhooks

    Returns:
        JSONResponse: A JSON object with counts and notification results.
    """
    print("\n" + "=" * 50)
    print("🔄 Refreshing all feeds...")
    print("=" * 50)

    # --- STEP 1: Record BEFORE counts ---
    # We snapshot the current counts so we can compare after
    # fetching to see what's NEW.
    before_summary = get_dashboard_summary()
    before_critical = before_summary.get("critical_cves", 0) if isinstance(before_summary, dict) else getattr(before_summary, "critical_cves", 0)
    before_high = before_summary.get("high_cves", 0) if isinstance(before_summary, dict) else getattr(before_summary, "high_cves", 0)
    before_cisa = before_summary.get("active_exploits", 0) if isinstance(before_summary, dict) else getattr(before_summary, "active_exploits", 0)

    # --- STEP 2: Fetch from each source ---
    # Each function returns the count of newly saved records.
    # We wrap each call in try/except so that if ONE source
    # fails, the others still get processed.
    results = {}

    try:
        results["cves_saved"] = fetch_and_store_cves()
    except Exception as e:
        print(f"❌ CVE fetch failed: {e}")
        results["cves_saved"] = 0

    try:
        results["epss_updated"] = fetch_epss_scores()
    except Exception as e:
        print(f"❌ EPSS fetch failed: {e}")
        results["epss_updated"] = 0

    try:
        results["cisa_saved"] = fetch_and_store_cisa_kev()
    except Exception as e:
        print(f"❌ CISA fetch failed: {e}")
        results["cisa_saved"] = 0

    try:
        results["articles_saved"] = fetch_and_store_rss()
    except Exception as e:
        print(f"❌ RSS fetch failed: {e}")
        results["articles_saved"] = 0

    try:
        results["threats_saved"] = fetch_all_threat_intel()
    except Exception as e:
        print(f"❌ Threat intel fetch failed: {e}")
        results["threats_saved"] = 0

    # --- STEP 3: Record AFTER counts and find new items ---
    after_summary = get_dashboard_summary()
    after_critical = after_summary.get("critical_cves", 0) if isinstance(after_summary, dict) else getattr(after_summary, "critical_cves", 0)
    after_high = after_summary.get("high_cves", 0) if isinstance(after_summary, dict) else getattr(after_summary, "high_cves", 0)
    after_cisa = after_summary.get("active_exploits", 0) if isinstance(after_summary, dict) else getattr(after_summary, "active_exploits", 0)

    new_critical_count = max(0, after_critical - before_critical)
    new_high_count = max(0, after_high - before_high)
    new_cisa_count = max(0, after_cisa - before_cisa)

    # --- STEP 4: Send webhook notifications for new items ---
    # Only send notifications if there are actually new items.
    # We fetch the newest items to include in the notification.
    try:
        new_critical_cves = []
        new_high_cves = []
        new_cisa_exploits = []

        if new_critical_count > 0:
            new_critical_cves = get_recent_cves(
                limit=new_critical_count, severity_filter="CRITICAL"
            )

        if new_high_count > 0:
            new_high_cves = get_recent_cves(
                limit=new_high_count, severity_filter="HIGH"
            )

        if new_cisa_count > 0:
            new_cisa_exploits = get_cisa_exploits(limit=new_cisa_count)

        notification_results = notify_all_webhooks(
            new_critical_cves=new_critical_cves,
            new_high_cves=new_high_cves,
            new_cisa_exploits=new_cisa_exploits,
        )
        results["notifications"] = notification_results
    except Exception as e:
        print(f"❌ Webhook notifications failed: {e}")
        results["notifications"] = {"error": str(e)}

    results["status"] = "complete"

    print("=" * 50)
    print(f"✅ Refresh complete: {results}")
    print("=" * 50 + "\n")

    # JSONResponse returns the results as JSON data.
    # JSON (JavaScript Object Notation) is the standard format
    # for sending data between a server and a web browser.
    return JSONResponse(content=results)


# ============================================================
# API ROUTE: Get CVEs as JSON (GET /api/cves)
# ============================================================
# This endpoint returns CVE data as raw JSON. This is useful
# for developers who want to access the data programmatically
# (without the HTML page).
#
# FastAPI auto-generates interactive documentation for this
# endpoint at http://localhost:8000/docs
# ============================================================

@app.get("/api/cves")
def api_get_cves(limit: int = 20, severity: str = None, start_date: str = None, end_date: str = None):
    """Return recent CVEs as JSON data with optional severity and date range filters."""
    return get_recent_cves(limit=limit, severity_filter=severity, start_date=start_date, end_date=end_date)


@app.get("/api/cisa")
def api_get_cisa_exploits(limit: int = 20, start_date: str = None, end_date: str = None):
    """Return CISA Known Exploited Vulnerabilities as JSON with optional date range filter."""
    return get_cisa_exploits(limit=limit, start_date=start_date, end_date=end_date)


@app.get("/api/news")
def api_get_news(limit: int = 30, source: str = None, start_date: str = None, end_date: str = None):
    """Return security news articles as JSON with optional source and date range filters."""
    return get_rss_articles(limit=limit, source_filter=source, start_date=start_date, end_date=end_date)


@app.get("/api/threats")
def api_get_threats(limit: int = 30, indicator_type: str = None, start_date: str = None, end_date: str = None):
    """Return threat indicators as JSON with optional type and date range filters."""
    return get_threat_indicators(limit=limit, indicator_type=indicator_type, start_date=start_date, end_date=end_date)


@app.get("/api/summary")
def api_get_summary(start_date: str = None, end_date: str = None):
    """Return dashboard summary statistics as JSON with optional date range filter."""
    return get_dashboard_summary(start_date=start_date, end_date=end_date)


# ============================================================
# PAGE ROUTE: Settings Page (GET /settings)
# ============================================================
# Renders the settings page where users can manage webhook
# configurations for automated notifications.
# ============================================================

@app.get("/settings")
def settings_page(request: Request):
    """
    Render the Settings page with all configured webhooks
    and the current schedule configuration.
    """
    webhooks = get_all_webhooks()
    schedule = get_scheduler_status()
    rss_feeds = get_all_rss_feeds()
    current_user = get_current_user_optional(request)

    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "request": request,
            "webhooks": webhooks,
            "schedule": schedule,
            "rss_feeds": rss_feeds,
            "is_authenticated": current_user is not None,
            "current_user": current_user or "",
        },
    )


# ============================================================
# PAGE ROUTE: Threat Actors Directory (GET /actors)
# ============================================================

@app.get("/actors")
def threat_actors_page(request: Request, search: str = None, sector: str = None):
    """
    Render the Threat Actors & Ransomware Groups directory page.
    """
    actors = get_all_threat_actors(search=search, sector=sector)
    current_user = get_current_user_optional(request)

    return templates.TemplateResponse(
        request=request,
        name="actors.html",
        context={
            "request": request,
            "actors": actors,
            "search": search or "",
            "sector": sector or "",
            "is_authenticated": current_user is not None,
            "current_user": current_user or "",
        },
    )


@app.get("/api/threat-actors")
def api_get_threat_actors(search: str = None, sector: str = None):
    """Return threat actor profiles as JSON with optional search and sector filters."""
    return get_all_threat_actors(search=search, sector=sector)


@app.get("/api/threat-actors/{actor_id}")
def api_get_threat_actor_detail(actor_id: int):
    """Return a single threat actor profile by ID."""
    actor = get_threat_actor_by_id(actor_id)
    if actor:
        return actor
    return JSONResponse(status_code=404, content={"error": "Threat actor not found"})


# ============================================================
# API ROUTES: Webhook CRUD (Create, Read, Update, Delete)
# ============================================================
# These endpoints let the Settings page manage webhooks via
# JavaScript fetch() calls.
#
# PYTHON CONCEPT — REST API Conventions:
#   GET    /api/webhooks       → List all webhooks
#   POST   /api/webhooks       → Create a new webhook
#   PUT    /api/webhooks/{id}  → Update a specific webhook
#   DELETE /api/webhooks/{id}  → Delete a specific webhook
#   POST   /api/webhooks/{id}/test   → Send a test notification
#   POST   /api/webhooks/{id}/toggle → Toggle active/inactive
# ============================================================

@app.get("/api/webhooks")
def api_list_webhooks():
    """Return all configured webhooks as JSON."""
    return get_all_webhooks()


@app.post("/api/webhooks")
def api_create_webhook(webhook: WebhookSchema, current_user: str = Depends(require_admin)):
    """
    Create a new webhook configuration.

    PYTHON CONCEPT — Pydantic Validation:
        FastAPI automatically validates the incoming JSON body
        against the WebhookSchema. If any field is missing or
        has the wrong type, FastAPI returns a 422 error with
        a detailed explanation — we don't have to write that
        validation code ourselves!

    Args:
        webhook: A WebhookSchema object (parsed from JSON body).

    Returns:
        JSONResponse: The new webhook's ID and a success message.
    """
    # webhook.model_dump() converts the Pydantic model to a
    # plain Python dictionary, which our save_webhook() expects.
    new_id = save_webhook(webhook.model_dump())
    return JSONResponse(
        content={"id": new_id, "message": "Webhook created successfully"},
        status_code=201,  # 201 = "Created"
    )


@app.put("/api/webhooks/{webhook_id}")
def api_update_webhook(webhook_id: int, webhook: WebhookSchema, current_user: str = Depends(require_admin)):
    """
    Update an existing webhook configuration.

    PYTHON CONCEPT — Path Parameters:
        {webhook_id} in the URL becomes a function parameter.
        FastAPI automatically converts it to an int because
        of the type hint "webhook_id: int".

    Args:
        webhook_id: The ID from the URL path (e.g. /api/webhooks/3).
        webhook: Updated webhook data from the JSON body.
    """
    success = update_webhook(webhook_id, webhook.model_dump())
    if success:
        return JSONResponse(content={"message": "Webhook updated successfully"})
    else:
        return JSONResponse(
            content={"error": "Webhook not found"},
            status_code=404,  # 404 = "Not Found"
        )


@app.delete("/api/webhooks/{webhook_id}")
def api_delete_webhook(webhook_id: int, current_user: str = Depends(require_admin)):
    """
    Delete a webhook configuration.

    Args:
        webhook_id: The ID of the webhook to delete.
    """
    success = delete_webhook(webhook_id)
    if success:
        return JSONResponse(content={"message": "Webhook deleted successfully"})
    else:
        return JSONResponse(
            content={"error": "Webhook not found"},
            status_code=404,
        )


@app.post("/api/webhooks/{webhook_id}/toggle")
def api_toggle_webhook(webhook_id: int, current_user: str = Depends(require_admin)):
    """
    Toggle a webhook between active and inactive.

    This is called by the toggle switch on the Settings page.
    Instead of requiring the full webhook data, it simply
    flips the is_active field.
    """
    success = toggle_webhook(webhook_id)
    if success:
        webhook = get_webhook_by_id(webhook_id)
        return JSONResponse(content={
            "message": "Webhook toggled",
            "is_active": bool(webhook["is_active"]) if webhook else False,
        })
    else:
        return JSONResponse(
            content={"error": "Webhook not found"},
            status_code=404,
        )


@app.post("/api/webhooks/{webhook_id}/test")
def api_test_webhook(webhook_id: int, current_user: str = Depends(require_admin)):
    """
    Send a test notification to a specific webhook.

    This lets users verify their webhook URL is correctly
    configured before relying on it for real alerts.
    """
    success = send_test_notification(webhook_id)
    if success:
        return JSONResponse(content={"message": "Test notification sent successfully!"})
    else:
        return JSONResponse(
            content={"error": "Failed to send test notification. Check the webhook URL."},
            status_code=400,  # 400 = "Bad Request"
        )


# ============================================================
# API ROUTES: Scheduled Refresh
# ============================================================
# These endpoints let the Settings page manage the automatic
# feed refresh schedule.
#
# PYTHON CONCEPT — Background Task Management:
#   When the user changes the schedule, we save the settings
#   to the database and then restart the scheduler thread.
#   The thread reads the new settings on startup, so it
#   automatically picks up the new interval.
# ============================================================

@app.get("/api/schedule")
def api_get_schedule():
    """Return the current schedule settings and status."""
    return get_scheduler_status()


@app.post("/api/schedule")
def api_update_schedule(request_data: dict, current_user: str = Depends(require_admin)):
    """
    Update the automatic refresh schedule.

    PYTHON CONCEPT — dict Parameter:
        FastAPI can accept a plain dict as the request body.
        We use this instead of a Pydantic model here because
        the schedule only has two simple fields (enabled and
        interval_hours).

    Args:
        request_data: JSON body with "enabled" (bool) and
                      "interval_hours" (int: 6, 12, 24, or 48).
    """
    enabled = request_data.get("enabled", False)
    interval_hours = request_data.get("interval_hours", 24)

    # Validate the interval
    from app.services.scheduler_service import VALID_INTERVALS
    if interval_hours not in VALID_INTERVALS:
        return JSONResponse(
            content={"error": f"Invalid interval. Must be one of: {VALID_INTERVALS}"},
            status_code=400,
        )

    # Save to database and restart the scheduler
    save_schedule_settings(enabled, interval_hours)
    restart_scheduler()

    # Return the updated status
    status = get_scheduler_status()
    return JSONResponse(content={
        "message": "Schedule updated successfully",
        **status,
    })


# ============================================================
# API ROUTES: RSS Feed Management
# ============================================================
# These endpoints let the Settings page add, remove, and toggle
# RSS feed sources. Feeds are stored in the rss_feeds database
# table and read during each data refresh.
# ============================================================

@app.get("/api/rss-feeds")
def api_list_rss_feeds():
    """Return all configured RSS feeds as JSON."""
    return get_all_rss_feeds()


@app.post("/api/rss-feeds")
def api_add_rss_feed(feed_data: dict, current_user: str = Depends(require_admin)):
    """
    Add a new RSS feed source.

    Args:
        feed_data: JSON body with "name" and "url" fields.
    """
    name = feed_data.get("name", "").strip()
    url = feed_data.get("url", "").strip()

    if not name or not url:
        return JSONResponse(
            content={"error": "Both 'name' and 'url' are required."},
            status_code=400,
        )

    new_id = add_rss_feed(name, url)
    if new_id:
        return JSONResponse(
            content={"id": new_id, "message": "RSS feed added successfully"},
            status_code=201,
        )
    else:
        return JSONResponse(
            content={"error": "This feed URL already exists."},
            status_code=409,  # 409 = Conflict
        )


@app.delete("/api/rss-feeds/{feed_id}")
def api_delete_rss_feed(feed_id: int, current_user: str = Depends(require_admin)):
    """Remove an RSS feed source."""
    success = delete_rss_feed(feed_id)
    if success:
        return JSONResponse(content={"message": "RSS feed removed"})
    else:
        return JSONResponse(
            content={"error": "Feed not found"},
            status_code=404,
        )


@app.post("/api/rss-feeds/{feed_id}/toggle")
def api_toggle_rss_feed(feed_id: int, current_user: str = Depends(require_admin)):
    """Toggle an RSS feed between active and inactive."""
    success = toggle_rss_feed(feed_id)
    if success:
        return JSONResponse(content={"message": "Feed toggled"})
    else:
        return JSONResponse(
            content={"error": "Feed not found"},
            status_code=404,
        )


# ============================================================
# RUN THE APPLICATION
# ============================================================
# This block runs ONLY when you execute this file directly:
#   python app/main.py
#
# It does NOT run when the file is imported by another module.
#
# PYTHON CONCEPT — if __name__ == "__main__":
#   Every Python file has a special variable called __name__.
#   - When you RUN the file directly: __name__ == "__main__"
#   - When you IMPORT the file:      __name__ == "app.main"
#
#   This lets us put startup code that should only execute
#   when the file is the "main" program, not when it's
#   imported as a library.
# ============================================================

if __name__ == "__main__":
    # uvicorn.run() starts the web server.
    # - "app.main:app" tells uvicorn where to find our FastAPI app
    #   (module "app.main", variable "app")
    # - host="0.0.0.0" makes the server accessible from any
    #   network interface (not just localhost)
    # - port=8000 is the port number to listen on
    # - reload=True auto-restarts the server when code changes
    #   (very handy during development!)
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
