# ============================================================
# app/database.py — SQLite Database Setup & Connection
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This file handles everything related to our SQLite database:
#   1. Creating the database file (cyber_dashboard.db)
#   2. Creating the tables (cves, cisa_exploits, rss_articles, etc.)
#   3. Providing a reusable function to connect to the database
#
# WHAT IS SQLite?
# ---------------
# SQLite is a lightweight relational database that stores ALL
# its data in a single file on your computer (no server needed).
# Python includes the "sqlite3" module in its standard library,
# so there is nothing extra to install.
#
# WHAT IS SQL?
# ------------
# SQL (Structured Query Language) is the language used to talk
# to databases. Common SQL commands include:
#   - CREATE TABLE: Define a new table with columns
#   - INSERT INTO:  Add new rows of data
#   - SELECT:       Read/query data from a table
#   - UPDATE:       Modify existing rows
#   - DELETE:       Remove rows
#
# PYTHON CONCEPTS COVERED:
# - The sqlite3 standard library module
# - Context managers (the "with" statement)
# - Multi-line strings (triple quotes)
# - Functions that return values
# ============================================================

# Import the built-in sqlite3 module. This comes with Python —
# no "pip install" required!
import sqlite3

# Import our config to get the DATABASE_PATH constant.
from app.config import DATABASE_PATH


def get_connection():
    """
    Create and return a connection to our SQLite database.

    WHAT IS A DATABASE CONNECTION?
    ------------------------------
    A "connection" is like opening a phone call to the database.
    You need an open connection to send SQL commands. When you
    are done, you should close it (like hanging up the phone).

    HOW THIS FUNCTION WORKS:
    ------------------------
    1. sqlite3.connect(path) opens (or creates) the database file.
    2. conn.row_factory = sqlite3.Row makes query results behave
       like dictionaries, so you can write row["cve_id"] instead
       of row[0]. This is much more readable!
    3. We return the connection object so other code can use it.

    Returns:
        sqlite3.Connection: An open connection to the database.
    """
    # Ensure the parent directory exists (e.g. /home/data on Azure App Service)
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # sqlite3.connect() opens the database file. If the file
    # does not exist yet, SQLite creates it automatically!
    # str(DATABASE_PATH) converts our Path object to a string
    # because sqlite3.connect() expects a string.
    conn = sqlite3.connect(str(DATABASE_PATH))

    # row_factory controls how query results are returned.
    # sqlite3.Row makes each row act like a dictionary, so
    # we can access columns by name: row["cve_id"]
    # Without this, we would have to use numeric indexes: row[0]
    conn.row_factory = sqlite3.Row

    return conn


def initialize_database():
    """
    Create all the database tables if they do not already exist.

    WHAT DOES "IF NOT EXISTS" MEAN?
    --------------------------------
    The SQL phrase "CREATE TABLE IF NOT EXISTS" means:
    - If the table already exists, do nothing (no error).
    - If the table does NOT exist, create it.
    This makes it safe to call this function every time the
    app starts — it will only create tables on the first run.

    WHAT IS A PRIMARY KEY?
    ----------------------
    A PRIMARY KEY is a column (or columns) that uniquely
    identifies each row. No two rows can have the same
    primary key value. For example, each CVE has a unique
    cve_id like "CVE-2024-1234".

    WHAT IS UNIQUE?
    ---------------
    The UNIQUE constraint means no two rows can have the same
    value in that column. For example, we don't want to store
    the same RSS article link twice.
    """
    # "with" is a CONTEXT MANAGER. It automatically handles
    # cleanup for us. When the "with" block ends, Python will
    # automatically close the database connection, even if an
    # error occurs inside the block.
    #
    # This is equivalent to writing:
    #   conn = get_connection()
    #   try:
    #       ... do work ...
    #   finally:
    #       conn.close()
    #
    # The "with" version is shorter and safer!
    with get_connection() as conn:

        # A "cursor" is an object that lets us execute SQL
        # commands on the database. Think of it as the "pen"
        # we use to write SQL statements.
        cursor = conn.cursor()

        # --------------------------------------------------
        # TABLE 1: cves
        # Stores vulnerability records from the NVD database.
        # --------------------------------------------------
        # Triple-quoted strings (""" ... """) let us write
        # text that spans multiple lines. This is very handy
        # for writing readable SQL queries.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id          TEXT UNIQUE NOT NULL,
                description     TEXT,
                severity        TEXT,
                cvss_score      REAL,
                epss_score      REAL,
                published_date  TEXT,
                last_modified   TEXT,
                fetched_at      TEXT DEFAULT (datetime('now'))
            )
        """)
        # Column explanations:
        # - id:             Auto-incrementing row number (1, 2, 3, ...)
        # - cve_id:         Unique CVE identifier like "CVE-2024-1234"
        # - description:    What the vulnerability does
        # - severity:       CRITICAL / HIGH / MEDIUM / LOW / NONE
        # - cvss_score:     Numeric severity score from 0.0 to 10.0
        # - epss_score:     Exploit probability from 0.0 to 1.0
        # - published_date: When the CVE was published
        # - last_modified:  When NVD last updated this CVE
        # - fetched_at:     When WE fetched this record (auto-filled)

        # --------------------------------------------------
        # TABLE 2: cisa_exploits
        # Stores CISA Known Exploited Vulnerabilities.
        # These are CVEs that attackers are ACTIVELY using.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cisa_exploits (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id              TEXT UNIQUE NOT NULL,
                vulnerability_name  TEXT,
                vendor_project      TEXT,
                product             TEXT,
                date_added          TEXT,
                short_description   TEXT,
                required_action     TEXT,
                due_date            TEXT,
                fetched_at          TEXT DEFAULT (datetime('now'))
            )
        """)

        # --------------------------------------------------
        # TABLE 3: rss_articles
        # Stores news articles from security RSS feeds.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rss_articles (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT,
                link        TEXT UNIQUE NOT NULL,
                source      TEXT,
                published   TEXT,
                summary     TEXT,
                fetched_at  TEXT DEFAULT (datetime('now'))
            )
        """)

        # --------------------------------------------------
        # TABLE 4: threat_indicators
        # Stores malicious URLs and IPs from Abuse.ch feeds.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type  TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                threat_type     TEXT,
                source          TEXT,
                date_added      TEXT,
                status          TEXT,
                fetched_at      TEXT DEFAULT (datetime('now')),
                UNIQUE(indicator_type, indicator_value)
            )
        """)
        # The UNIQUE(indicator_type, indicator_value) constraint
        # means the COMBINATION of type + value must be unique.
        # For example, we can have:
        #   ("url", "http://evil.com")   — allowed
        #   ("ip", "1.2.3.4")           — allowed
        #   ("url", "http://evil.com")   — BLOCKED (duplicate!)

        # --------------------------------------------------
        # TABLE 5: fetch_log
        # Tracks when each data source was last refreshed.
        # This helps us decide if cached data is still fresh.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fetch_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT UNIQUE NOT NULL,
                last_fetch  TEXT NOT NULL,
                status      TEXT,
                record_count INTEGER DEFAULT 0
            )
        """)

        # --------------------------------------------------
        # TABLE 6: webhooks
        # Stores webhook configurations for sending automated
        # notifications to external platforms (Slack, Discord,
        # Microsoft Teams, or any generic webhook endpoint).
        #
        # BEGINNER CONCEPT — Using INTEGER as Boolean:
        #   SQLite does not have a native BOOLEAN type.
        #   Instead, we use INTEGER with values 0 (False)
        #   and 1 (True). The DEFAULT 1 means "enabled."
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                name                  TEXT NOT NULL,
                platform              TEXT NOT NULL,
                webhook_url           TEXT NOT NULL,
                is_active             INTEGER DEFAULT 1,
                notify_critical_cves  INTEGER DEFAULT 1,
                notify_high_cves      INTEGER DEFAULT 1,
                notify_cisa_exploits  INTEGER DEFAULT 1,
                last_notified         TEXT,
                created_at            TEXT DEFAULT (datetime('now'))
            )
        """)
        # Column explanations:
        # - name:                 Friendly label (e.g. "SOC Slack Channel")
        # - platform:             "slack", "discord", "teams", or "generic"
        # - webhook_url:          The full webhook URL provided by the platform
        # - is_active:            1 = enabled, 0 = paused (toggle on/off)
        # - notify_critical_cves: 1 = send alerts for CRITICAL CVEs
        # - notify_high_cves:     1 = send alerts for HIGH CVEs
        # - notify_cisa_exploits: 1 = send alerts for new CISA entries
        # - last_notified:        Timestamp of last notification (rate limiting)
        # - created_at:           When this webhook was configured

        # --------------------------------------------------
        # TABLE 7: rss_feeds
        # Stores the list of RSS feed sources that the app
        # monitors for security news. Users can add or remove
        # feeds from the Settings page.
        #
        # BEGINNER CONCEPT — Separating Config from Code:
        #   Instead of hardcoding feed URLs in config.py, we
        #   store them in the database. This lets users manage
        #   feeds without editing Python files.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rss_feeds (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                url        TEXT UNIQUE NOT NULL,
                is_active  INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)

        # --------------------------------------------------
        # TABLE 8: users
        # Stores user accounts, roles (admin/analyst/viewer),
        # and secure bcrypt-hashed passwords.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                role            TEXT DEFAULT 'viewer',
                last_login      TEXT,
                created_at      TEXT DEFAULT (datetime('now')),
                updated_at      TEXT DEFAULT (datetime('now'))
            )
        """)

        # Migration: Ensure role & last_login columns exist on users
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer'")
        except Exception:
            pass

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
        except Exception:
            pass

        # Ensure admin user has role='admin'
        try:
            cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin' AND (role IS NULL OR role = 'viewer')")
        except Exception:
            pass

        # --------------------------------------------------
        # TABLE 9: threat_actors
        # Stores threat actor and ransomware group profiles.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_actors (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                name             TEXT UNIQUE NOT NULL,
                aliases          TEXT,
                origin           TEXT,
                threat_type      TEXT,
                target_sectors   TEXT,
                description      TEXT,
                associated_cves  TEXT,
                mitre_ttps       TEXT,
                status           TEXT DEFAULT 'Active / High Threat',
                created_at       TEXT DEFAULT (datetime('now')),
                updated_at       TEXT DEFAULT (datetime('now'))
            )
        """)

        # --------------------------------------------------
        # TABLE 10: detection_rules
        # Stores Sigma and YARA detection rules mapped to TTPs.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT UNIQUE NOT NULL,
                rule_type       TEXT NOT NULL,
                mitre_ttp       TEXT,
                severity        TEXT DEFAULT 'HIGH',
                target_cve      TEXT,
                description     TEXT,
                code_content    TEXT NOT NULL,
                target_siem     TEXT DEFAULT 'Generic',
                deployment_guide TEXT,
                created_at      TEXT DEFAULT (datetime('now')),
                updated_at      TEXT DEFAULT (datetime('now'))
            )
        """)

        # --------------------------------------------------
        # TABLE 11: investigation_history
        # Tracks IOC lookups performed by analysts.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigation_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator       TEXT NOT NULL,
                indicator_type  TEXT NOT NULL,
                verdict         TEXT NOT NULL,
                threat_score    INTEGER NOT NULL,
                threat_tags     TEXT,
                geo_country     TEXT,
                created_at      TEXT DEFAULT (datetime('now'))
            )
        """)

        # --------------------------------------------------
        # TABLE 12: audit_logs
        # Tamper-evident cryptographic audit log chained with SHA-256.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT DEFAULT (datetime('now')),
                username        TEXT NOT NULL,
                role            TEXT NOT NULL,
                action          TEXT NOT NULL,
                resource_type   TEXT,
                resource_id     TEXT,
                status          TEXT NOT NULL,
                ip_address      TEXT,
                details         TEXT,
                prev_hash       TEXT,
                integrity_hash  TEXT NOT NULL
            )
        """)

        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(username)")
        except Exception:
            pass

        # Migration: Ensure deployment_guide column exists on existing DBs
        try:
            cursor.execute("ALTER TABLE detection_rules ADD COLUMN deployment_guide TEXT")
        except Exception:
            pass  # Column already exists

        # Deduplication: Remove any duplicate detection rules by title
        cursor.execute("""
            DELETE FROM detection_rules
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM detection_rules
                GROUP BY LOWER(TRIM(title))
            )
        """)

        # Migration: Add Unique Index on title to guarantee no duplicates
        try:
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_rules_title ON detection_rules(title)")
        except Exception:
            pass

        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicators_val ON threat_indicators(indicator_value)")
        except Exception:
            pass

        # --------------------------------------------------
        # TABLE 13: security_policies
        # Stores minimum password requirement configurations.
        # --------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_policies (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                min_length         INTEGER DEFAULT 10,
                require_uppercase  INTEGER DEFAULT 1,
                require_lowercase  INTEGER DEFAULT 1,
                require_numbers    INTEGER DEFAULT 1,
                require_special    INTEGER DEFAULT 1,
                updated_at         TEXT DEFAULT (datetime('now'))
            )
        """)

        # Initialize default security policy if empty
        cursor.execute("SELECT COUNT(*) as count FROM security_policies")
        if cursor.fetchone()["count"] == 0:
            cursor.execute("""
                INSERT INTO security_policies (min_length, require_uppercase, require_lowercase, require_numbers, require_special)
                VALUES (10, 1, 1, 1, 1)
            """)

        conn.commit()

    # When the "with" block ends here, the connection is
    # automatically closed. The database file is saved.
    print("✅ Database initialized successfully!")
    print(f"   Database file: {DATABASE_PATH}")

    # Seed default RSS feeds
    seed_default_rss_feeds()

    # Seed default admin user
    from app.services.auth_service import seed_default_admin_user
    seed_default_admin_user()

    # Seed default threat actors
    from app.services.threat_actor_service import seed_default_threat_actors
    seed_default_threat_actors()

    # Seed default detection rules
    from app.services.rule_service import seed_default_detection_rules
    seed_default_detection_rules()


def seed_default_rss_feeds():
    """
    Populate the rss_feeds table with default security news sources
    if it is empty. This runs on every startup but only INSERTs
    feeds that don't already exist (using INSERT OR IGNORE).

    PYTHON CONCEPT — Idempotent Operations:
        An "idempotent" operation produces the same result no
        matter how many times you run it. INSERT OR IGNORE is
        idempotent — if the URL already exists, it silently
        skips the insert instead of raising an error.
    """
    # These are the same feeds that were originally hardcoded
    # in config.py. They serve as sensible defaults.
    from app.config import RSS_FEEDS

    with get_connection() as conn:
        cursor = conn.cursor()

        # Check if the table already has feeds
        cursor.execute("SELECT COUNT(*) as count FROM rss_feeds")
        row = cursor.fetchone()

        if row["count"] > 0:
            # Table already has data — skip seeding
            return

        # Insert the default feeds
        for feed in RSS_FEEDS:
            cursor.execute("""
                INSERT OR IGNORE INTO rss_feeds (name, url)
                VALUES (?, ?)
            """, (feed["name"], feed["url"]))

        conn.commit()
        print(f"   📡 Seeded {len(RSS_FEEDS)} default RSS feeds.")

