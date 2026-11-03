# ============================================================
# app/config.py — Application Configuration & Settings
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This file stores all the settings, URLs, and constants that
# the rest of the application needs. By keeping them in one
# place, we avoid "magic strings" scattered across files and
# make it easy to change a URL or setting without hunting
# through multiple files.
#
# PYTHON CONCEPTS COVERED:
# - Dictionaries (dict): key-value data storage
# - Lists (list): ordered collections of items
# - Constants: variables written in ALL_CAPS by convention
# - The pathlib module: modern file path handling
# ============================================================

# "import" brings code from other modules into this file.
# "pathlib" is a built-in Python module for working with
# file system paths (folders and files) in a clean way.
import os
from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================
# Path(__file__) gives us the full path to THIS file (config.py).
# .parent goes up one directory (from app/config.py -> app/).
# .parent again goes up once more (from app/ -> cyber_dashboard/).
#
# This is called "relative path resolution" — it works no
# matter where the project is installed on someone's computer.
# ============================================================

# The root directory of our entire project
BASE_DIR = Path(__file__).parent.parent

# The directory where our FastAPI "app" package lives
APP_DIR = Path(__file__).parent

# Durable installation profile and SQLite path. Ordinary startup never creates
# or adopts a database; operator provisioning is explicit.
from app.storage.local import data_directory, load_manifest, enabled, private_read, StorageError, require_sqlite_backend
APP_DATA_DIR = data_directory()
STORAGE_PROFILE = load_manifest(APP_DATA_DIR)
for _name, _value in (STORAGE_PROFILE or {}).get('settings', {}).items():
    os.environ.setdefault(_name, _value)
ALLOW_EPHEMERAL_STORAGE = enabled(os.getenv('ALLOW_EPHEMERAL_STORAGE', str((STORAGE_PROFILE or {}).get('ephemeral', False))))
EXPECTED_DATABASE_ID = os.getenv('EXPECTED_DATABASE_ID', '')
_db_env = os.getenv("DATABASE_PATH")
if _db_env is not None and not _db_env.strip(): raise StorageError('configuration_invalid')
DATABASE_PATH = Path(_db_env).expanduser().absolute() if _db_env else Path((STORAGE_PROFILE or {}).get('database_path', str(APP_DATA_DIR/'cyber_dashboard.db')))
require_sqlite_backend()


# ============================================================
# SECURITY & AUTHENTICATION CONFIGURATION
# ============================================================
_key_file = os.getenv('JWT_SECRET_KEY_FILE')
if _key_file is not None and (not _key_file.strip() or not Path(_key_file).is_absolute()):
    raise StorageError('configuration_invalid')
if 'JWT_SECRET_KEY' in os.environ and _key_file is not None:
    raise RuntimeError('Set JWT_SECRET_KEY or JWT_SECRET_KEY_FILE, not both.')
if 'JWT_SECRET_KEY' in os.environ:
    JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']
else:
    _key_file = _key_file or (STORAGE_PROFILE or {}).get('signing_key_file')
    JWT_SECRET_KEY = private_read(Path(_key_file), maximum=4096).rstrip('\r\n') if _key_file else ''
if len(JWT_SECRET_KEY.encode("utf-8")) < 32 or JWT_SECRET_KEY == "cyberdash-secret-key-change-in-production-2026":
    raise RuntimeError("Set JWT_SECRET_KEY to a unique, randomly generated secret of at least 32 bytes before starting CyberDash.")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
FEATURE_ASSET_PRIORITIZATION = os.getenv("FEATURE_ASSET_PRIORITIZATION", "false").lower() in ("1", "true", "yes")
FEATURE_ASSET_MONITORING = os.getenv("FEATURE_ASSET_MONITORING", "false").lower() in ("1", "true", "yes")
FEATURE_ASSET_DISCOVERY = os.getenv("FEATURE_ASSET_DISCOVERY", "false").lower() in ("1", "true", "yes")
FEATURE_CASE_MANAGEMENT = os.getenv("FEATURE_CASE_MANAGEMENT", "false").lower() in ("1", "true", "yes")
FEATURE_RULE_LIFECYCLE = os.getenv("FEATURE_RULE_LIFECYCLE", "false").lower() in ("1", "true", "yes")
# Unset permits RFC1918 only; an explicit override replaces (never extends) it.
# Preserve an explicitly empty value as the operator's deny-all switch.
DEFAULT_ASSET_PROBE_ALLOWED_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
ASSET_PROBE_ALLOWED_CIDRS = os.getenv("ASSET_PROBE_ALLOWED_CIDRS", DEFAULT_ASSET_PROBE_ALLOWED_CIDRS)
ASSET_PROBE_SCOPE_LABEL = os.getenv("ASSET_PROBE_SCOPE_LABEL", "local")[:80]
ASSET_PROBE_RATE_PER_MINUTE = int(os.getenv("ASSET_PROBE_RATE_PER_MINUTE", "10"))
ASSET_DISCOVERY_RATE_PER_MINUTE = int(os.getenv("ASSET_DISCOVERY_RATE_PER_MINUTE", "60"))
ASSET_PROBE_DNS_RATE_PER_MINUTE = int(os.getenv("ASSET_PROBE_DNS_RATE_PER_MINUTE", "60"))
if any(not 1 <= value <= 600 for value in (ASSET_PROBE_RATE_PER_MINUTE, ASSET_DISCOVERY_RATE_PER_MINUTE, ASSET_PROBE_DNS_RATE_PER_MINUTE)):
    raise RuntimeError("Asset network rates must be between 1 and 600 attempts/minute.")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
ASSET_INTEL_STALE_HOURS = int(os.getenv("ASSET_INTEL_STALE_HOURS", "48"))
if ASSET_INTEL_STALE_HOURS < 1:
    raise RuntimeError("ASSET_INTEL_STALE_HOURS must be positive.")

DEFAULT_ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")


# ============================================================
# EXTERNAL API ENDPOINTS
# ============================================================
# These are the URLs where we fetch security data from.
# Each one is a public, free API or data feed.
#
# A "constant" in Python is just a regular variable, but
# by convention we write it in ALL_UPPERCASE to signal
# "this value should not be changed at runtime."
# ============================================================

# --- NVD (National Vulnerability Database) API v2.0 ---
# This is the official US government database of software
# vulnerabilities. Each vulnerability gets a "CVE" identifier
# like CVE-2024-1234.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- FIRST EPSS (Exploit Prediction Scoring System) API ---
# EPSS predicts the probability that a CVE will be exploited
# in the wild within the next 30 days. A score of 0.95 means
# there is a 95% chance attackers will use this vulnerability.
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# --- CISA KEV (Known Exploited Vulnerabilities) Catalog ---
# CISA maintains a list of vulnerabilities that are ACTIVELY
# being exploited by attackers right now. This is a JSON file
# that gets updated regularly.
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# --- Abuse.ch URLhaus ---
# URLhaus tracks malicious URLs used for distributing malware.
# This public CSV feed contains recently reported active malicious URLs.
URLHAUS_RECENT_URL = os.getenv("URLHAUS_RECENT_URL", "https://urlhaus.abuse.ch/downloads/csv_recent/")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")

# --- Abuse.ch Feodo Tracker ---
# Feodo Tracker tracks botnet Command & Control (C2) servers.
# These are IP addresses used by attackers to control malware.
FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"


# ============================================================
# RSS FEED SOURCES
# ============================================================
# RSS (Really Simple Syndication) is a standard format for
# publishing news articles. Websites publish an RSS "feed"
# (an XML file) that programs can read to get the latest
# articles automatically.
#
# Below is a Python LIST of DICTIONARIES. Each dictionary
# has two keys: "name" (a friendly label) and "url" (the
# RSS feed address).
#
# PYTHON CONCEPT — List of Dictionaries:
#   my_list = [
#       {"key1": "value1", "key2": "value2"},
#       {"key1": "value3", "key2": "value4"},
#   ]
#   Access: my_list[0]["key1"]  →  "value1"
# ============================================================

RSS_FEEDS = [
    {
        "name": "CISA Cybersecurity Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/",
    },
]


# ============================================================
# CACHE & FETCH SETTINGS
# ============================================================
# These control how often we refresh data from external APIs.
# Fetching too frequently can get us rate-limited (blocked).
# ============================================================

# How many seconds to keep cached data before refreshing.
# 900 seconds = 15 minutes.
CACHE_TTL_SECONDS = 900

# How many seconds to wait for an external API to respond
# before giving up. 15 seconds is a reasonable timeout.
HTTP_TIMEOUT_SECONDS = 15

# How many recent CVEs to request from NVD per fetch.
# The NVD API can return up to 2000 per request.
NVD_RESULTS_PER_PAGE = 2000
