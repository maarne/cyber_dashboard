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
from fastapi import FastAPI, Request

# StaticFiles lets us serve CSS, JS, and image files.
# Jinja2Templates lets us render HTML templates with data.
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# JSONResponse lets us return JSON data from API endpoints.
from fastapi.responses import JSONResponse

# Import our own modules (from the app/ package)
from app.config import APP_DIR
from app.database import initialize_database

# Import the data fetcher services
from app.services.cve_service import fetch_and_store_cves, fetch_epss_scores
from app.services.cisa_service import fetch_and_store_cisa_kev
from app.services.rss_service import fetch_and_store_rss
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
def dashboard_home(request: Request, start_date: str = None, end_date: str = None):
    """
    Render the main dashboard page with data filtered by optional date range.
    """
    summary = get_dashboard_summary(start_date=start_date, end_date=end_date)
    cves = get_recent_cves(limit=50, start_date=start_date, end_date=end_date)
    cisa_exploits = get_cisa_exploits(limit=50, start_date=start_date, end_date=end_date)
    articles = get_rss_articles(limit=50, start_date=start_date, end_date=end_date)
    threats = get_threat_indicators(limit=50, start_date=start_date, end_date=end_date)
    rss_sources = get_rss_sources()

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
        },
    )


# ============================================================
# API ROUTE: Refresh All Feeds (POST /api/refresh)
# ============================================================
# This endpoint triggers a fresh data fetch from all external
# sources. It's called by the "Refresh Feeds" button in the UI.
#
# POST is used instead of GET because this action CHANGES data
# (it writes new records to the database). By convention:
#   - GET = read/retrieve data (no side effects)
#   - POST = create/modify data (has side effects)
# ============================================================

@app.post("/api/refresh")
def refresh_all_feeds():
    """
    Fetch fresh data from all external sources and store in the database.

    This endpoint is called by the JavaScript refresh button.
    It fetches data from NVD, CISA, RSS feeds, and Abuse.ch,
    then returns a summary of what was fetched.

    Returns:
        JSONResponse: A JSON object with counts of saved records.
    """
    print("\n" + "=" * 50)
    print("🔄 Refreshing all feeds...")
    print("=" * 50)

    # Fetch from each source. Each function returns the count
    # of newly saved records.
    #
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
