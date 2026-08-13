# ============================================================
# app/main.py — FastAPI Application Entry Point & RBAC Controller
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This is the main file that starts the entire web application.
# It defines the FastAPI "app" object, sets up routes (URLs),
# establishes Role-Based Access Control (RBAC) security dependencies,
# records tamper-evident cryptographic audit logs, and connects
# backend services to the frontend templates.
#
# ROLE-BASED ACCESS CONTROL (RBAC) TIERS:
# ---------------------------------------
# - Admin: Full governance, user management, webhooks, RSS feeds, scheduler, rules.
# - Analyst: Threat triage, rule authoring, webhook testing, manual refreshes, audit viewing.
# - Viewer / Unauthenticated: Read-only visibility across dashboards and intelligence.
#
# PYTHON CONCEPTS COVERED:
# - Decorators (@app.get, @app.post, @app.put, @app.delete)
# - FastAPI Lifespan context manager for startup/shutdown tasks
# - Dependency Injection with FastAPI Depends()
# - Cryptographic Audit Logging integration
# - Secure HTTP-only cookies and CORS/SSRF defenses
# ============================================================

from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, Response, RedirectResponse

# Import auth & RBAC service
from app.services.auth_service import (
    verify_password,
    create_access_token,
    verify_access_token,
    get_user_by_username,
    list_all_users,
    create_user,
    update_user_role,
    delete_user_by_username,
    update_user_password,
    record_user_login,
    seed_default_admin_user,
    generate_secure_random_password,
    get_password_policy,
    update_password_policy,
    validate_password_against_policy,
    is_initial_setup_required,
    complete_initial_setup,
)

# Import cryptographic audit logging service
from app.services.audit_service import (
    log_audit_event,
    get_audit_logs,
    verify_audit_log_integrity,
    export_audit_logs_csv,
    export_audit_logs_json,
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

# Import the webhook notification service
from app.services.webhook_service import (
    get_all_webhooks,
    get_webhook_by_id,
    save_webhook,
    update_webhook,
    delete_webhook,
    toggle_webhook,
    notify_all_webhooks,
    send_test_notification,
    is_safe_external_url,
)

# Import Pydantic models & schemas
from app.models.schemas import (
    WebhookSchema,
    DetectionRuleSchema,
    LoginRequest,
    ChangePasswordRequest,
    UserCreateSchema,
    UserUpdateRoleSchema,
    PasswordPolicySchema,
    InitialSetupSchema,
)

# Import the background scheduler service
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

# Import detection rule repository service
from app.services.rule_service import (
    get_all_detection_rules,
    get_rule_by_id,
    save_detection_rule,
    update_detection_rule,
    delete_detection_rule,
)

# Import MITRE ATT&CK intelligence service
from app.services.mitre_service import get_mitre_ttp_details

# Import CVE intelligence service
from app.services.cve_intel_service import get_cve_details

# Import IOC Investigator intelligence service
from app.services.ioc_service import (
    investigate_ioc,
    get_recent_investigations,
    clear_investigation_history,
)


# ============================================================
# LIFESPAN CONTEXT MANAGER — Server Startup and Shutdown
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events cleanly:
    1. Initialize SQLite database & indexes.
    2. Seed default RBAC users (admin, analyst, viewer).
    3. Start background automated refresh scheduler.
    """
    print("🚀 Starting CyberDash — Cyber Security Dashboard")
    print("=" * 50)
    initialize_database()
    seed_default_admin_user()
    print("=" * 50)
    print("🌐 Dashboard available at: http://127.0.0.1:8000")
    print("📚 API documentation at:   http://127.0.0.1:8000/docs")
    print("=" * 50)

    # Start the background scheduler if enabled
    start_scheduler()

    yield

    print("🛑 CyberDash shutting down gracefully...")


app = FastAPI(
    title="CyberDash — Cyber Security Dashboard",
    description="Enterprise cyber intelligence dashboard with granular RBAC, detection rules, and cryptographic audit logs.",
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================
# FIRST-TIME SETUP REDIRECTION MIDDLEWARE
# ============================================================

@app.middleware("http")
async def setup_redirection_middleware(request: Request, call_next):
    """
    Ensure users are directed to the First-Time Setup Wizard if no admin account exists.
    """
    path = request.url.path
    if is_initial_setup_required():
        allowed_prefixes = ("/static", "/favicon.ico")
        allowed_paths = ("/setup", "/api/setup", "/api/security/password-policy", "/api/security/generate-password")
        if not (any(path.startswith(p) for p in allowed_prefixes) or path in allowed_paths):
            return RedirectResponse(url="/setup", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    elif path == "/setup":
        return RedirectResponse(url="/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    return await call_next(request)



# ============================================================
# RBAC SECURITY & DEPENDENCY INJECTION HELPERS
# ============================================================

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request headers or socket."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_current_user_and_role(request: Request) -> dict | None:
    """
    Validate access token from cookie or Authorization header.
    Returns: {"username": str, "role": str} if authenticated, else None.
    """
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    if token:
        return verify_access_token(token)
    return None


def get_current_user_optional(request: Request) -> str | None:
    """Convenience helper returning just the username if authenticated."""
    info = get_current_user_and_role(request)
    return info.get("username") if info else None


def get_template_auth_context(request: Request) -> dict:
    """
    Build standardized Jinja template context for user status, role, and permissions.
    """
    info = get_current_user_and_role(request)
    if not info:
        return {
            "is_authenticated": False,
            "current_user": "",
            "user_role": "",
            "is_admin": False,
            "is_analyst": False,
            "is_viewer": False,
        }
    role = info.get("role", "viewer")
    return {
        "is_authenticated": True,
        "current_user": info.get("username", ""),
        "user_role": role,
        "is_admin": role == "admin",
        "is_analyst": role in ("admin", "analyst"),
        "is_viewer": role == "viewer",
    }


def require_authenticated_user(request: Request) -> dict:
    """FastAPI Dependency: requires any valid logged-in user (admin, analyst, or viewer)."""
    user_info = get_current_user_and_role(request)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
        )
    return user_info


def require_analyst_or_admin(request: Request) -> dict:
    """FastAPI Dependency: requires Analyst or Admin RBAC role."""
    user_info = require_authenticated_user(request)
    role = user_info.get("role", "viewer")
    if role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied. Analyst or Administrator privileges required.",
        )
    return user_info


def require_admin(request: Request) -> dict:
    """FastAPI Dependency: requires Administrator RBAC role."""
    user_info = require_authenticated_user(request)
    if user_info.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied. Administrator privileges required.",
        )
    return user_info


# ============================================================
# MOUNT STATIC FILES & JINJA2 TEMPLATES
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory=str(APP_DIR / "static")),
    name="static",
)

templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
templates.env.globals["get_mitre_ttp"] = get_mitre_ttp_details
templates.env.globals["get_cve_details"] = get_cve_details


# ============================================================
# PAGE ROUTE: First-Time Setup Wizard (GET /setup)
# ============================================================

@app.get("/setup")
def setup_wizard_page(request: Request):
    """Render the first-time administrator onboarding wizard."""
    if not is_initial_setup_required():
        return RedirectResponse(url="/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    policy = get_password_policy()
    return templates.TemplateResponse(
        request=request,
        name="setup.html",
        context={
            "request": request,
            "password_policy": policy,
        },
    )


# ============================================================
# PAGE ROUTE: Home Page (GET /)
# ============================================================

@app.get("/")
def dashboard_home(request: Request, start_date: str = None, end_date: str = None, search: str = None, q: str = None):
    """Render the main dashboard page."""
    search_query = (search or q or "").strip()
    summary = get_dashboard_summary(start_date=start_date, end_date=end_date)
    cve_limit = 100 if search_query else 50
    cves = get_recent_cves(limit=cve_limit, start_date=start_date, end_date=end_date, search_query=search_query)
    cisa_exploits = get_cisa_exploits(limit=50, start_date=start_date, end_date=end_date)
    articles = get_rss_articles(limit=50, start_date=start_date, end_date=end_date)
    threats = get_threat_indicators(limit=50, start_date=start_date, end_date=end_date)
    rss_sources = get_rss_sources()

    auth_ctx = get_template_auth_context(request)

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
            **auth_ctx,
        },
    )


# ============================================================
# PAGE ROUTE: Threat Actors Directory (GET /actors)
# ============================================================

@app.get("/actors")
def threat_actors_page(request: Request, search: str = None, sector: str = None):
    """Render the Threat Actors & Ransomware Groups directory page."""
    actors = get_all_threat_actors(search=search, sector=sector)
    auth_ctx = get_template_auth_context(request)

    return templates.TemplateResponse(
        request=request,
        name="actors.html",
        context={
            "request": request,
            "actors": actors,
            "search": search or "",
            "sector": sector or "",
            **auth_ctx,
        },
    )


# ============================================================
# PAGE ROUTE: Detection Rule Repository (GET /rules)
# ============================================================

@app.get("/rules")
def detection_rules_page(request: Request, rule_type: str = "ALL", search: str = None, siem: str = "ALL"):
    """Render the MITRE ATT&CK TTP & Detection Rule Repository page."""
    rules = get_all_detection_rules(rule_type=rule_type, search=search, siem=siem)
    auth_ctx = get_template_auth_context(request)

    return templates.TemplateResponse(
        request=request,
        name="rules.html",
        context={
            "request": request,
            "rules": rules,
            "rule_type": rule_type.upper() if rule_type else "ALL",
            "search": search or "",
            "siem": siem.upper() if siem else "ALL",
            **auth_ctx,
        },
    )


# ============================================================
# PAGE ROUTE: IOC Investigator (GET /investigate)
# ============================================================

@app.get("/investigate")
def ioc_investigator_page(request: Request, ioc: str = ""):
    """Render the Threat Intelligence & IOC Investigator triage console."""
    auth_ctx = get_template_auth_context(request)
    recent_history = get_recent_investigations(limit=10)
    
    dossier = None
    if ioc.strip():
        dossier = investigate_ioc(ioc.strip())

    return templates.TemplateResponse(
        request=request,
        name="investigate.html",
        context={
            "request": request,
            "ioc": ioc.strip(),
            "dossier": dossier,
            "history": recent_history,
            **auth_ctx,
        },
    )


# ============================================================
# PAGE ROUTE: Settings, RBAC & Audit Console (GET /settings)
# ============================================================

@app.get("/settings")
def settings_page(request: Request):
    """
    Render the Settings page with Webhooks, Schedules, RSS Feeds,
    User Management (Admin only), and Audit Logs (Analyst/Admin).
    """
    webhooks = get_all_webhooks()
    schedule = get_scheduler_status()
    rss_feeds = get_all_rss_feeds()
    auth_ctx = get_template_auth_context(request)

    # Fetch users for User Management panel (Admin only)
    users_list = list_all_users() if auth_ctx["is_admin"] else []

    # Fetch audit logs & cryptographic verification (Analyst or Admin)
    audit_logs_list = get_audit_logs(limit=25) if auth_ctx["is_analyst"] else []
    audit_integrity = verify_audit_log_integrity() if auth_ctx["is_analyst"] else {}

    # Fetch active password security policy
    password_policy = get_password_policy()

    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "request": request,
            "webhooks": webhooks,
            "schedule": schedule,
            "rss_feeds": rss_feeds,
            "users": users_list,
            "audit_logs": audit_logs_list,
            "audit_integrity": audit_integrity,
            "password_policy": password_policy,
            **auth_ctx,
        },
    )


# ============================================================
# FIRST-TIME SETUP API ENDPOINT
# ============================================================

@app.post("/api/setup")
def api_initial_setup(payload: InitialSetupSchema, request: Request):
    """Initialize primary administrator credentials for first-time use."""
    client_ip = get_client_ip(request)

    if not is_initial_setup_required():
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Initial setup has already been completed. Access denied."},
        )

    try:
        user_record = complete_initial_setup(payload.username, payload.password)
    except ValueError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": str(e)},
        )

    # Issue administrator JWT cookie
    token = create_access_token(username=user_record["username"], role="admin")
    record_user_login(user_record["username"])

    log_audit_event(
        username=user_record["username"],
        role="admin",
        action="INITIAL_SETUP_COMPLETED",
        resource_type="SYSTEM",
        status="SUCCESS",
        details="Initial administrator account created and environment secured.",
        ip_address=client_ip,
    )

    is_https = request.url.scheme == "https"
    res = JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "status": "success",
            "message": "Administrator account configured successfully!",
            "redirect": "/",
        },
    )
    res.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=is_https,
        samesite="lax",
        max_age=86400,
    )
    return res


# ============================================================
# AUTHENTICATION & SESSION API ENDPOINTS
# ============================================================

@app.post("/api/auth/login")
def api_login(credentials: LoginRequest, request: Request):
    """Authenticate user credentials and issue role-bearing JWT cookie."""
    client_ip = get_client_ip(request)
    user = get_user_by_username(credentials.username.strip())

    if not user or not verify_password(credentials.password, user["password_hash"]):
        log_audit_event(
            username=credentials.username.strip() or "anonymous",
            role="anonymous",
            action="AUTH_LOGIN_FAILED",
            resource_type="AUTH",
            status="FAILED",
            details="Invalid username or password attempt.",
            ip_address=client_ip,
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"status": "error", "message": "Invalid username or password"},
        )

    # Success: record login timestamp & generate token
    record_user_login(user["username"])
    user_role = user.get("role", "viewer")
    token = create_access_token(username=user["username"], role=user_role)

    log_audit_event(
        username=user["username"],
        role=user_role,
        action="AUTH_LOGIN_SUCCESS",
        resource_type="AUTH",
        status="SUCCESS",
        details=f"User successfully logged in with role: {user_role}",
        ip_address=client_ip,
    )

    res = JSONResponse(content={
        "status": "success",
        "username": user["username"],
        "role": user_role,
    })
    
    is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto") == "https"
        or os.getenv("ENV") == "production"
    )
    res.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=is_https,
        samesite="lax",
        max_age=86400,
    )
    return res


@app.post("/api/auth/logout")
def api_logout(request: Request):
    """Log out current user and invalidate cookie."""
    client_ip = get_client_ip(request)
    user_info = get_current_user_and_role(request)
    
    if user_info:
        log_audit_event(
            username=user_info["username"],
            role=user_info["role"],
            action="AUTH_LOGOUT",
            resource_type="AUTH",
            status="SUCCESS",
            details="User logged out session.",
            ip_address=client_ip,
        )

    res = JSONResponse(content={"status": "success", "message": "Logged out successfully"})
    res.delete_cookie("access_token")
    return res


@app.get("/api/auth/me")
def api_get_current_user_info(request: Request):
    """Return authenticated user profile and permissions."""
    info = get_current_user_and_role(request)
    if not info:
        return {
            "is_authenticated": False,
            "username": "",
            "role": "anonymous",
            "is_admin": False,
            "is_analyst": False,
            "is_viewer": False,
        }
    role = info.get("role", "viewer")
    return {
        "is_authenticated": True,
        "username": info["username"],
        "role": role,
        "is_admin": role == "admin",
        "is_analyst": role in ("admin", "analyst"),
        "is_viewer": role == "viewer",
    }


@app.post("/api/auth/change-password")
def api_change_password(
    req: ChangePasswordRequest,
    request: Request,
    user_info: dict = Depends(require_authenticated_user),
):
    """Update password for the currently logged-in account."""
    client_ip = get_client_ip(request)
    username = user_info["username"]
    user = get_user_by_username(username)

    if not user or not verify_password(req.current_password, user["password_hash"]):
        log_audit_event(
            username=username,
            role=user_info["role"],
            action="PASSWORD_CHANGE_FAILED",
            resource_type="USER",
            resource_id=username,
            status="FAILED",
            details="Incorrect current password provided.",
            ip_address=client_ip,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Current password is incorrect."},
        )

    # Validate new password against active password security policy
    is_valid, err_msg = validate_password_against_policy(req.new_password.strip())
    if not is_valid:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": err_msg},
        )

    update_user_password(username, req.new_password.strip())

    log_audit_event(
        username=username,
        role=user_info["role"],
        action="PASSWORD_CHANGED",
        resource_type="USER",
        resource_id=username,
        status="SUCCESS",
        details="User password updated successfully.",
        ip_address=client_ip,
    )
    return JSONResponse(content={"message": "Password updated successfully."})


# ============================================================
# USER LIFECYCLE MANAGEMENT API ENDPOINTS (Admin Only)
# ============================================================

@app.get("/api/users")
def api_list_users(admin: dict = Depends(require_admin)):
    """List all registered users (Admin only)."""
    return list_all_users()


@app.post("/api/users")
def api_create_user(
    user_data: UserCreateSchema,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Create a new user with assigned role (Admin only)."""
    client_ip = get_client_ip(request)
    username = user_data.username.strip()

    if not username or not user_data.password:
        return JSONResponse(
            status_code=400,
            content={"error": "Username and password are required."},
        )

    # Validate candidate password against active password security policy
    is_valid, err_msg = validate_password_against_policy(user_data.password)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"error": err_msg},
        )

    if get_user_by_username(username):
        return JSONResponse(
            status_code=409,
            content={"error": f"Username '{username}' already exists."},
        )

    created = create_user(
        username=username,
        password=user_data.password,
        role=user_data.role,
    )

    log_audit_event(
        username=admin["username"],
        role=admin["role"],
        action="USER_CREATED",
        resource_type="USER",
        resource_id=username,
        status="SUCCESS",
        details=f"Created user '{username}' with role '{user_data.role}'",
        ip_address=client_ip,
    )

    return JSONResponse(
        status_code=201,
        content={"message": f"User '{username}' created successfully.", "user": created},
    )


# ============================================================
# SECURITY & PASSWORD POLICY API ENDPOINTS
# ============================================================

@app.get("/api/security/password-policy")
def api_get_password_policy():
    """Return the active minimum password security requirements."""
    return get_password_policy()


@app.post("/api/security/password-policy")
def api_update_password_policy(
    policy: PasswordPolicySchema,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Update minimum password security requirements (Admin only)."""
    client_ip = get_client_ip(request)
    updated = update_password_policy(
        min_length=policy.min_length,
        require_uppercase=policy.require_uppercase,
        require_lowercase=policy.require_lowercase,
        require_numbers=policy.require_numbers,
        require_special=policy.require_special,
    )

    log_audit_event(
        username=admin["username"],
        role=admin["role"],
        action="PASSWORD_POLICY_UPDATED",
        resource_type="SECURITY_POLICY",
        status="SUCCESS",
        details=f"Updated password policy: min_length={policy.min_length}, upper={policy.require_uppercase}, lower={policy.require_lowercase}, num={policy.require_numbers}, special={policy.require_special}",
        ip_address=client_ip,
    )

    return JSONResponse(content={"message": "Password policy updated successfully.", "policy": updated})


@app.get("/api/security/generate-password")
def api_generate_compliant_password(length: int = 10):
    """Generate a cryptographically random compliant password."""
    pwd = generate_secure_random_password(length)
    return {"password": pwd}



@app.put("/api/users/{username}/role")
def api_update_user_role(
    username: str,
    role_data: UserUpdateRoleSchema,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Update a user's RBAC role (Admin only)."""
    client_ip = get_client_ip(request)
    target_user = get_user_by_username(username)

    if not target_user:
        return JSONResponse(status_code=404, content={"error": "User not found."})

    success, message = update_user_role(username, role_data.role)
    if not success:
        return JSONResponse(status_code=400, content={"error": message})

    log_audit_event(
        username=admin["username"],
        role=admin["role"],
        action="USER_ROLE_UPDATED",
        resource_type="USER",
        resource_id=username,
        status="SUCCESS",
        details=f"Updated user '{username}' role to '{role_data.role}'",
        ip_address=client_ip,
    )

    return {"message": message}



@app.delete("/api/users/{username}")
def api_delete_user(
    username: str,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Delete a user account (Admin only)."""
    client_ip = get_client_ip(request)
    if username == admin["username"]:
        return JSONResponse(status_code=400, content={"error": "You cannot delete your own account."})

    success = delete_user_by_username(username)
    if not success:
        return JSONResponse(status_code=400, content={"error": "Cannot delete this user."})

    log_audit_event(
        username=admin["username"],
        role=admin["role"],
        action="USER_DELETED",
        resource_type="USER",
        resource_id=username,
        status="SUCCESS",
        details=f"Deleted user account '{username}'",
        ip_address=client_ip,
    )

    return {"message": f"User '{username}' deleted successfully."}


# ============================================================
# TAMPER-EVIDENT AUDIT LOGGING API ENDPOINTS
# ============================================================

@app.get("/api/audit-logs")
def api_get_audit_logs(
    limit: int = 50,
    action: str = None,
    search: str = None,
    user: dict = Depends(require_analyst_or_admin),
):
    """Retrieve audit logs (Analyst or Admin)."""
    return get_audit_logs(limit=limit, action_filter=action, search=search)


@app.get("/api/audit-logs/verify")
def api_verify_audit_logs(user: dict = Depends(require_analyst_or_admin)):
    """Verify cryptographic SHA-256 integrity hash chain."""
    return verify_audit_log_integrity()


@app.get("/api/audit-logs/export")
def api_export_audit_logs(
    format: str = "csv",
    request: Request = None,
    admin: dict = Depends(require_admin),
):
    """Export complete audit ledger as CSV or JSON (Admin only)."""
    client_ip = get_client_ip(request)

    log_audit_event(
        username=admin["username"],
        role=admin["role"],
        action="AUDIT_LOG_EXPORTED",
        resource_type="AUDIT",
        status="SUCCESS",
        details=f"Exported audit ledger in {format.upper()} format.",
        ip_address=client_ip,
    )

    if format.lower() == "json":
        data = export_audit_logs_json()
        return JSONResponse(content=data)

    csv_data = export_audit_logs_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="cyberdash_audit_ledger.csv"'},
    )


# ============================================================
# API ROUTE: Refresh All Feeds (POST /api/refresh) — Analyst/Admin
# ============================================================

@app.post("/api/refresh")
def refresh_all_feeds(
    request: Request,
    user: dict = Depends(require_analyst_or_admin),
):
    """Fetch fresh data from all external sources and notify webhooks."""
    client_ip = get_client_ip(request)
    print("\n" + "=" * 50)
    print("🔄 Refreshing all feeds...")
    print("=" * 50)

    before_summary = get_dashboard_summary()
    before_critical = before_summary.get("critical_cves", 0) if isinstance(before_summary, dict) else getattr(before_summary, "critical_cves", 0)
    before_high = before_summary.get("high_cves", 0) if isinstance(before_summary, dict) else getattr(before_summary, "high_cves", 0)
    before_cisa = before_summary.get("active_exploits", 0) if isinstance(before_summary, dict) else getattr(before_summary, "active_exploits", 0)

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

    after_summary = get_dashboard_summary()
    after_critical = after_summary.get("critical_cves", 0) if isinstance(after_summary, dict) else getattr(after_summary, "critical_cves", 0)
    after_high = after_summary.get("high_cves", 0) if isinstance(after_summary, dict) else getattr(after_summary, "high_cves", 0)
    after_cisa = after_summary.get("active_exploits", 0) if isinstance(after_summary, dict) else getattr(after_summary, "active_exploits", 0)

    new_critical_count = max(0, after_critical - before_critical)
    new_high_count = max(0, after_high - before_high)
    new_cisa_count = max(0, after_cisa - before_cisa)

    try:
        new_critical_cves = []
        new_high_cves = []
        new_cisa_exploits = []

        if new_critical_count > 0:
            new_critical_cves = get_recent_cves(limit=new_critical_count, severity_filter="CRITICAL")
        if new_high_count > 0:
            new_high_cves = get_recent_cves(limit=new_high_count, severity_filter="HIGH")
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

    log_audit_event(
        username=user["username"],
        role=user["role"],
        action="FEED_REFRESH_TRIGGERED",
        resource_type="FEED",
        status="SUCCESS",
        details=f"Manual refresh completed: CVEs={results.get('cves_saved', 0)}, CISA={results.get('cisa_saved', 0)}, News={results.get('articles_saved', 0)}, Threats={results.get('threats_saved', 0)}",
        ip_address=client_ip,
    )

    return JSONResponse(content=results)


# ============================================================
# API ROUTES: Data Query Endpoints
# ============================================================

@app.get("/api/cves")
def api_get_cves(limit: int = 20, severity: str = None, start_date: str = None, end_date: str = None):
    return get_recent_cves(limit=limit, severity_filter=severity, start_date=start_date, end_date=end_date)


@app.get("/api/cisa")
def api_get_cisa_exploits(limit: int = 20, start_date: str = None, end_date: str = None):
    return get_cisa_exploits(limit=limit, start_date=start_date, end_date=end_date)


@app.get("/api/news")
def api_get_news(limit: int = 30, source: str = None, start_date: str = None, end_date: str = None):
    return get_rss_articles(limit=limit, source_filter=source, start_date=start_date, end_date=end_date)


@app.get("/api/threats")
def api_get_threats(limit: int = 30, indicator_type: str = None, start_date: str = None, end_date: str = None):
    return get_threat_indicators(limit=limit, indicator_type=indicator_type, start_date=start_date, end_date=end_date)


@app.get("/api/summary")
def api_get_summary(start_date: str = None, end_date: str = None):
    return get_dashboard_summary(start_date=start_date, end_date=end_date)


@app.get("/api/threat-actors")
def api_get_threat_actors(search: str = None, sector: str = None):
    return get_all_threat_actors(search=search, sector=sector)


@app.get("/api/threat-actors/{actor_id}")
def api_get_threat_actor_detail(actor_id: int):
    actor = get_threat_actor_by_id(actor_id)
    if actor:
        return actor
    return JSONResponse(status_code=404, content={"error": "Threat actor not found"})


@app.get("/api/mitre-ttps/{ttp_id}")
def api_get_mitre_ttp_info(ttp_id: str):
    return get_mitre_ttp_details(ttp_id)


@app.get("/api/cve-intel/{cve_id}")
def api_get_cve_intel_info(cve_id: str):
    return get_cve_details(cve_id)


@app.get("/api/investigate")
def api_investigate_ioc(ioc: str = ""):
    if not ioc.strip():
        return JSONResponse(status_code=400, content={"error": "IOC parameter is required."})
    return investigate_ioc(ioc.strip())


@app.get("/api/investigate/history")
def api_get_investigate_history(limit: int = 15):
    return get_recent_investigations(limit=limit)


@app.delete("/api/investigate/history")
def api_clear_investigate_history(request: Request, admin: dict = Depends(require_admin)):
    client_ip = get_client_ip(request)
    success = clear_investigation_history()
    if success:
        log_audit_event(
            username=admin["username"],
            role=admin["role"],
            action="HISTORY_CLEARED",
            resource_type="INVESTIGATION",
            status="SUCCESS",
            details="Cleared all past IOC investigation triage history.",
            ip_address=client_ip,
        )
        return {"message": "Investigation history cleared successfully."}
    return JSONResponse(status_code=500, content={"error": "Failed to clear history."})


# ============================================================
# API ROUTES: Detection Rules CRUD (Analyst or Admin)
# ============================================================

@app.get("/api/detection-rules")
def api_list_detection_rules(rule_type: str = "ALL", search: str = None, siem: str = "ALL"):
    return get_all_detection_rules(rule_type=rule_type, search=search, siem=siem)


@app.get("/api/detection-rules/{rule_id}")
def api_get_detection_rule_detail(rule_id: int):
    rule = get_rule_by_id(rule_id)
    if rule:
        return rule
    return JSONResponse(status_code=404, content={"error": "Detection rule not found"})


@app.post("/api/detection-rules")
def api_create_detection_rule(
    rule: DetectionRuleSchema,
    request: Request,
    user: dict = Depends(require_analyst_or_admin),
):
    import sqlite3
    client_ip = get_client_ip(request)
    try:
        new_id = save_detection_rule(rule.model_dump())
    except sqlite3.IntegrityError:
        return JSONResponse(
            status_code=409,
            content={"error": f"A detection rule with the title '{rule.title}' already exists."},
        )

    log_audit_event(
        username=user["username"],
        role=user["role"],
        action="RULE_CREATED",
        resource_type="RULE",
        resource_id=rule.title,
        status="SUCCESS",
        details=f"Created {rule.rule_type} rule: {rule.title}",
        ip_address=client_ip,
    )

    return JSONResponse(
        content={"id": new_id, "message": "Detection rule created successfully"},
        status_code=201,
    )


@app.put("/api/detection-rules/{rule_id}")
def api_update_detection_rule(
    rule_id: int,
    rule: DetectionRuleSchema,
    request: Request,
    user: dict = Depends(require_analyst_or_admin),
):
    client_ip = get_client_ip(request)
    success = update_detection_rule(rule_id, rule.model_dump())
    if success:
        log_audit_event(
            username=user["username"],
            role=user["role"],
            action="RULE_UPDATED",
            resource_type="RULE",
            resource_id=f"#{rule_id} ({rule.title})",
            status="SUCCESS",
            details=f"Updated {rule.rule_type} rule #{rule_id}: {rule.title}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"message": "Detection rule updated successfully"})
    return JSONResponse(status_code=404, content={"error": "Detection rule not found"})


@app.delete("/api/detection-rules/{rule_id}")
def api_delete_detection_rule(
    rule_id: int,
    request: Request,
    user: dict = Depends(require_analyst_or_admin),
):
    client_ip = get_client_ip(request)
    rule = get_rule_by_id(rule_id)
    rule_title = rule["title"] if rule else f"#{rule_id}"

    success = delete_detection_rule(rule_id)
    if success:
        log_audit_event(
            username=user["username"],
            role=user["role"],
            action="RULE_DELETED",
            resource_type="RULE",
            resource_id=rule_title,
            status="SUCCESS",
            details=f"Deleted rule #{rule_id}: {rule_title}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"message": "Detection rule deleted successfully"})
    return JSONResponse(status_code=404, content={"error": "Detection rule not found"})


# ============================================================
# API ROUTES: Webhooks CRUD (Admin Only)
# ============================================================

@app.get("/api/webhooks")
def api_list_webhooks():
    return get_all_webhooks()


@app.post("/api/webhooks")
def api_create_webhook(
    webhook: WebhookSchema,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    is_safe, err_msg = is_safe_external_url(webhook.webhook_url)
    if not is_safe:
        return JSONResponse(status_code=400, content={"error": f"Invalid webhook URL: {err_msg}"})

    new_id = save_webhook(webhook.model_dump())

    log_audit_event(
        username=admin["username"],
        role=admin["role"],
        action="WEBHOOK_CREATED",
        resource_type="WEBHOOK",
        resource_id=webhook.name,
        status="SUCCESS",
        details=f"Created {webhook.platform} webhook: {webhook.name}",
        ip_address=client_ip,
    )

    return JSONResponse(
        content={"id": new_id, "message": "Webhook created successfully"},
        status_code=201,
    )


@app.put("/api/webhooks/{webhook_id}")
def api_update_webhook(
    webhook_id: int,
    webhook: WebhookSchema,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    is_safe, err_msg = is_safe_external_url(webhook.webhook_url)
    if not is_safe:
        return JSONResponse(status_code=400, content={"error": f"Invalid webhook URL: {err_msg}"})

    success = update_webhook(webhook_id, webhook.model_dump())
    if success:
        log_audit_event(
            username=admin["username"],
            role=admin["role"],
            action="WEBHOOK_UPDATED",
            resource_type="WEBHOOK",
            resource_id=f"#{webhook_id} ({webhook.name})",
            status="SUCCESS",
            details=f"Updated webhook #{webhook_id}: {webhook.name}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"message": "Webhook updated successfully"})
    return JSONResponse(status_code=404, content={"error": "Webhook not found"})


@app.delete("/api/webhooks/{webhook_id}")
def api_delete_webhook(
    webhook_id: int,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    wb = get_webhook_by_id(webhook_id)
    wb_name = wb["name"] if wb else f"#{webhook_id}"

    success = delete_webhook(webhook_id)
    if success:
        log_audit_event(
            username=admin["username"],
            role=admin["role"],
            action="WEBHOOK_DELETED",
            resource_type="WEBHOOK",
            resource_id=wb_name,
            status="SUCCESS",
            details=f"Deleted webhook #{webhook_id}: {wb_name}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"message": "Webhook deleted successfully"})
    return JSONResponse(status_code=404, content={"error": "Webhook not found"})


@app.post("/api/webhooks/{webhook_id}/toggle")
def api_toggle_webhook(
    webhook_id: int,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    success = toggle_webhook(webhook_id)
    if success:
        webhook = get_webhook_by_id(webhook_id)
        is_active = bool(webhook["is_active"]) if webhook else False
        log_audit_event(
            username=admin["username"],
            role=admin["role"],
            action="WEBHOOK_TOGGLED",
            resource_type="WEBHOOK",
            resource_id=f"#{webhook_id}",
            status="SUCCESS",
            details=f"Toggled webhook #{webhook_id} to active={is_active}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"message": "Webhook toggled", "is_active": is_active})
    return JSONResponse(status_code=404, content={"error": "Webhook not found"})


@app.post("/api/webhooks/{webhook_id}/test")
def api_test_webhook(
    webhook_id: int,
    request: Request,
    user: dict = Depends(require_analyst_or_admin),
):
    client_ip = get_client_ip(request)
    success = send_test_notification(webhook_id)
    
    log_audit_event(
        username=user["username"],
        role=user["role"],
        action="WEBHOOK_TESTED",
        resource_type="WEBHOOK",
        resource_id=f"#{webhook_id}",
        status="SUCCESS" if success else "FAILED",
        details=f"Test notification to webhook #{webhook_id} result: {'Success' if success else 'Failed'}",
        ip_address=client_ip,
    )

    if success:
        return JSONResponse(content={"message": "Test notification sent successfully!"})
    return JSONResponse(
        status_code=400,
        content={"error": "Failed to send test notification. Check the webhook URL."},
    )


# ============================================================
# API ROUTES: Schedule & RSS Feeds (Admin Only)
# ============================================================

@app.get("/api/schedule")
def api_get_schedule():
    return get_scheduler_status()


@app.post("/api/schedule")
def api_update_schedule(
    request_data: dict,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    enabled = request_data.get("enabled", False)
    interval_hours = request_data.get("interval_hours", 24)

    from app.services.scheduler_service import VALID_INTERVALS
    if interval_hours not in VALID_INTERVALS:
        return JSONResponse(
            content={"error": f"Invalid interval. Must be one of: {VALID_INTERVALS}"},
            status_code=400,
        )

    save_schedule_settings(enabled, interval_hours)
    restart_scheduler()

    log_audit_event(
        username=admin["username"],
        role=admin["role"],
        action="SCHEDULE_UPDATED",
        resource_type="SCHEDULE",
        status="SUCCESS",
        details=f"Schedule updated: enabled={enabled}, interval={interval_hours}h",
        ip_address=client_ip,
    )

    status_data = get_scheduler_status()
    return JSONResponse(content={"message": "Schedule updated successfully", **status_data})


@app.get("/api/rss-feeds")
def api_list_rss_feeds():
    return get_all_rss_feeds()


@app.post("/api/rss-feeds")
def api_add_rss_feed(
    feed_data: dict,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    name = feed_data.get("name", "").strip()
    url = feed_data.get("url", "").strip()

    if not name or not url:
        return JSONResponse(status_code=400, content={"error": "Both 'name' and 'url' are required."})

    is_safe, err_msg = is_safe_external_url(url)
    if not is_safe:
        return JSONResponse(status_code=400, content={"error": f"Invalid RSS feed URL: {err_msg}"})

    new_id = add_rss_feed(name, url)
    if new_id:
        log_audit_event(
            username=admin["username"],
            role=admin["role"],
            action="RSS_FEED_CREATED",
            resource_type="FEED",
            resource_id=name,
            status="SUCCESS",
            details=f"Added RSS feed '{name}': {url}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"id": new_id, "message": "RSS feed added successfully"}, status_code=201)
    return JSONResponse(status_code=409, content={"error": "This feed URL already exists."})


@app.delete("/api/rss-feeds/{feed_id}")
def api_delete_rss_feed(
    feed_id: int,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    success = delete_rss_feed(feed_id)
    if success:
        log_audit_event(
            username=admin["username"],
            role=admin["role"],
            action="RSS_FEED_DELETED",
            resource_type="FEED",
            resource_id=f"#{feed_id}",
            status="SUCCESS",
            details=f"Deleted RSS feed source #{feed_id}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"message": "RSS feed removed"})
    return JSONResponse(status_code=404, content={"error": "Feed not found"})


@app.post("/api/rss-feeds/{feed_id}/toggle")
def api_toggle_rss_feed(
    feed_id: int,
    request: Request,
    admin: dict = Depends(require_admin),
):
    client_ip = get_client_ip(request)
    success = toggle_rss_feed(feed_id)
    if success:
        log_audit_event(
            username=admin["username"],
            role=admin["role"],
            action="RSS_FEED_TOGGLED",
            resource_type="FEED",
            resource_id=f"#{feed_id}",
            status="SUCCESS",
            details=f"Toggled RSS feed #{feed_id}",
            ip_address=client_ip,
        )
        return JSONResponse(content={"message": "Feed toggled"})
    return JSONResponse(status_code=404, content={"error": "Feed not found"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
