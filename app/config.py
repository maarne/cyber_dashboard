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

# The full file path to our SQLite database file.
# By default, it is created inside the project root, but can be
# overridden via the DATABASE_PATH environment variable (e.g. for Azure).
_db_env = os.getenv("DATABASE_PATH")
DATABASE_PATH = Path(_db_env) if _db_env else BASE_DIR / "cyber_dashboard.db"


# ============================================================
# SECURITY & AUTHENTICATION CONFIGURATION
# ============================================================
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cyberdash-secret-key-change-in-production-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

DEFAULT_ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "cyberdash123!")


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
NVD_RESULTS_PER_PAGE = 20
