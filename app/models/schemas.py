# ============================================================
# app/models/schemas.py — Pydantic Data Models (Schemas)
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This file defines "schemas" — blueprints that describe the
# shape of our data. Think of a schema like a form template:
# it says what fields exist and what type each field must be.
#
# WHAT IS Pydantic?
# -----------------
# Pydantic is a Python library that validates data for us.
# If we define a schema that says "cvss_score must be a float"
# and someone passes in a string like "abc", Pydantic will
# raise an error immediately. This prevents bugs!
#
# WHY USE SCHEMAS?
# ----------------
# External APIs return messy, unpredictable data. Schemas let
# us normalize that data into a clean, consistent format that
# the rest of our application can rely on.
#
# PYTHON CONCEPTS COVERED:
# - Classes: blueprints for creating objects
# - Type hints: telling Python what type a variable should be
# - Optional types: values that can be None (missing)
# - Inheritance: one class building on another
# - Default values: fallback values when data is missing
# ============================================================

# "from typing import Optional" imports the Optional type hint.
# Optional[str] means "this value is either a string OR None".
# None is Python's way of saying "no value" or "missing".
from typing import Optional

# BaseModel is the foundation class from Pydantic.
# All our schemas will "inherit" from it, which gives them
# automatic data validation and type checking.
from pydantic import BaseModel


# ============================================================
# CVE (Common Vulnerabilities and Exposures) Schema
# ============================================================
# This schema represents a single vulnerability from the NVD.
#
# PYTHON CONCEPT — Classes:
#   A class is like a blueprint or template. When we create
#   an instance of CVESchema, Python fills in the fields:
#
#   my_cve = CVESchema(
#       cve_id="CVE-2024-1234",
#       description="Buffer overflow in...",
#       severity="HIGH",
#       cvss_score=7.5
#   )
#   print(my_cve.cve_id)  →  "CVE-2024-1234"
#
# PYTHON CONCEPT — Inheritance:
#   "class CVESchema(BaseModel)" means CVESchema inherits
#   from BaseModel. This gives CVESchema all of Pydantic's
#   validation powers without us having to write that code.
# ============================================================

class CVESchema(BaseModel):
    """
    Represents a single CVE vulnerability record.

    Attributes:
        cve_id:         Unique identifier like "CVE-2024-1234"
        description:    What the vulnerability does
        severity:       Rating: CRITICAL, HIGH, MEDIUM, LOW, or NONE
        cvss_score:     Numeric severity from 0.0 to 10.0
        epss_score:     Exploit probability from 0.0 to 1.0
        published_date: When the CVE was published
        last_modified:  When it was last updated
    """

    # PYTHON CONCEPT — Type Hints:
    # The ": str" after cve_id means "this field must be a string".
    # Type hints don't enforce types at runtime by default, but
    # Pydantic DOES enforce them, which is one reason we use it.
    cve_id: str

    # Optional[str] means this field can be a string OR None.
    # "= None" sets the default value to None (if not provided).
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    published_date: Optional[str] = None
    last_modified: Optional[str] = None


# ============================================================
# CISA Known Exploited Vulnerability Schema
# ============================================================
# This represents a vulnerability that CISA has confirmed is
# being actively exploited by attackers in the real world.
# ============================================================

class CISAExploitSchema(BaseModel):
    """
    Represents a CISA Known Exploited Vulnerability.

    These are vulnerabilities that attackers are CURRENTLY
    using to compromise systems. Organizations are required
    to patch these within the specified due date.
    """

    cve_id: str
    vulnerability_name: Optional[str] = None
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    date_added: Optional[str] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[str] = None


# ============================================================
# RSS Article Schema
# ============================================================
# Represents a single news article from a security RSS feed.
# ============================================================

class RSSArticleSchema(BaseModel):
    """
    Represents a news article parsed from an RSS feed.

    Attributes:
        title:     Headline of the article
        link:      URL to the full article
        source:    Which RSS feed it came from
        published: Publication date as a string
        summary:   Short preview/excerpt of the article
    """

    title: Optional[str] = None
    link: str
    source: Optional[str] = None
    published: Optional[str] = None
    summary: Optional[str] = None


# ============================================================
# Threat Indicator Schema
# ============================================================
# Represents a single Indicator of Compromise (IoC) such as
# a malicious URL or a botnet Command & Control IP address.
# ============================================================

class ThreatIndicatorSchema(BaseModel):
    """
    Represents a threat indicator (IoC — Indicator of Compromise).

    Attributes:
        indicator_type:  "url" or "ip"
        indicator_value: The actual malicious URL or IP address
        threat_type:     Category of threat (e.g., "malware_download")
        source:          Where we got this data (e.g., "URLhaus")
        date_added:      When it was reported
        status:          Current status (e.g., "online", "offline")
    """

    indicator_type: str
    indicator_value: str
    threat_type: Optional[str] = None
    source: Optional[str] = None
    date_added: Optional[str] = None
    status: Optional[str] = None


# ============================================================
# Dashboard Summary Schema
# ============================================================
# A summary of counts displayed at the top of the dashboard.
# This is used by the main page to show quick statistics.
# ============================================================

class DashboardSummary(BaseModel):
    """
    Summary statistics shown on the dashboard homepage.

    These numbers give a quick overview of the current
    security landscape at a glance.
    """

    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    active_exploits: int = 0
    total_articles: int = 0
    total_threats: int = 0


# ============================================================
# Webhook Configuration Schema
# ============================================================
# Represents a configured webhook endpoint for sending
# automated notifications to external platforms like
# Slack, Discord, Microsoft Teams, or any generic URL.
#
# PYTHON CONCEPT — Boolean Fields with Defaults:
#   "is_active: bool = True" means this field defaults to True
#   if the caller doesn't provide a value. This makes creating
#   a new webhook simple — you only NEED to provide name,
#   platform, and webhook_url.
# ============================================================

class WebhookSchema(BaseModel):
    """
    Represents a webhook configuration for notifications.

    Attributes:
        name:                Friendly label (e.g. "SOC Slack Channel")
        platform:            Target platform: "slack", "discord", "teams", "generic"
        webhook_url:         The full incoming webhook URL
        is_active:           Whether this webhook is enabled
        notify_critical_cves:  Send alerts for CRITICAL CVEs
        notify_high_cves:      Send alerts for HIGH CVEs
        notify_cisa_exploits:  Send alerts for new CISA entries
    """

    name: str
    platform: str
    webhook_url: str
    is_active: bool = True
    notify_critical_cves: bool = True
    notify_high_cves: bool = True
    notify_cisa_exploits: bool = True


# ============================================================
# Detection Rule Schema
# ============================================================
class DetectionRuleSchema(BaseModel):
    """
    Represents a Sigma or YARA detection rule.
    """

    title: str
    rule_type: str = "Sigma"
    mitre_ttp: Optional[str] = None
    severity: Optional[str] = "HIGH"
    target_cve: Optional[str] = None
    description: Optional[str] = None
    code_content: str
    target_siem: Optional[str] = "Generic"
    deployment_guide: Optional[str] = None


# ============================================================
# User & RBAC Authentication Schemas
# ============================================================

class LoginRequest(BaseModel):
    """Payload for user authentication."""
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    """Payload for password update."""
    current_password: str
    new_password: str


class UserCreateSchema(BaseModel):
    """Payload for administrative user creation."""
    username: str
    password: str
    role: str = "viewer"


class UserUpdateRoleSchema(BaseModel):
    """Payload for updating user RBAC role."""
    role: str


class PasswordPolicySchema(BaseModel):
    """Payload for updating password security requirements."""
    min_length: int = 10
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = True


class InitialSetupSchema(BaseModel):
    """Payload for the first-time administrator initialization wizard."""
    username: str = "admin"
    password: str


class ApiTokenCreateSchema(BaseModel):
    """Payload for generating developer API tokens."""
    name: str
    role: str = "viewer"
    expires_in_days: Optional[int] = None
    rate_limit_per_min: Optional[int] = 60





