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

        # conn.commit() saves all the changes we just made to
        # the database file on disk. Without commit(), the
        # changes would be lost when the connection closes!
        conn.commit()

    # When the "with" block ends here, the connection is
    # automatically closed. The database file is saved.
    print("✅ Database initialized successfully!")
    print(f"   Database file: {DATABASE_PATH}")
