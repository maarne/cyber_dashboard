"""Ordered, additive migrations, called inside the startup write transaction."""


def apply_migrations(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    if conn.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone():
        return
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(cves)")}
    if "epss_fetched_at" not in columns:
        conn.execute("ALTER TABLE cves ADD COLUMN epss_fetched_at TEXT")
    if "last_success" not in {r["name"] for r in conn.execute("PRAGMA table_info(fetch_log)")}:
        conn.execute("ALTER TABLE fetch_log ADD COLUMN last_success TEXT")
    conn.execute("UPDATE fetch_log SET last_success=last_fetch WHERE status='success'")
    statements = [
        """CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, external_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL, environment TEXT NOT NULL, owner_team TEXT NOT NULL DEFAULT '',
            criticality INTEGER NOT NULL CHECK(criticality BETWEEN 1 AND 4),
            exposure TEXT NOT NULL CHECK(exposure IN ('internet','internal','unknown')),
            is_archived INTEGER NOT NULL DEFAULT 0 CHECK(is_archived IN (0,1)),
            row_version INTEGER NOT NULL DEFAULT 1,
            created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_by_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL,
            created_by TEXT NOT NULL, updated_by TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE asset_tags (
            asset_id INTEGER NOT NULL REFERENCES assets(id), tag TEXT NOT NULL,
            PRIMARY KEY(asset_id, tag)
        )""",
        """CREATE TABLE asset_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL REFERENCES assets(id),
            vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL,
            vendor_key TEXT NOT NULL, product_key TEXT NOT NULL, version_key TEXT NOT NULL,
            cpe TEXT, source TEXT NOT NULL, observed_at TEXT NOT NULL,
            row_version INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL, updated_by TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(asset_id, vendor_key, product_key, version_key)
        )""",
        """CREATE TABLE asset_cve_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL REFERENCES assets(id),
            cve_id TEXT NOT NULL, software_id INTEGER REFERENCES asset_software(id) ON DELETE RESTRICT,
            source TEXT NOT NULL, confidence TEXT NOT NULL CHECK(confidence IN ('confirmed','suspected')),
            evidence_note TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('open','in_progress','remediated','not_affected','accepted_risk')),
            reason TEXT NOT NULL DEFAULT '', accepted_risk_expires_at TEXT,
            row_version INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL, updated_by TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(asset_id, cve_id)
        )""",
        """CREATE TABLE asset_assessment_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES asset_cve_assessments(id),
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL,
            actor_name TEXT NOT NULL, before_json TEXT, after_json TEXT NOT NULL,
            audit_event_id INTEGER NOT NULL REFERENCES audit_logs(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE asset_inventory_state (
            id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL DEFAULT 0
        )""",
        "INSERT INTO asset_inventory_state(id) VALUES (1)",
        """CREATE TABLE asset_import_previews (
            token_hash TEXT PRIMARY KEY, actor_key TEXT NOT NULL, inventory_revision INTEGER NOT NULL,
            payload_json TEXT, payload_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
            consumed_at INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""",
        "CREATE INDEX idx_assets_filters ON assets(is_archived, environment, criticality)",
        "CREATE INDEX idx_asset_tags_lookup ON asset_tags(tag, asset_id)",
        "CREATE INDEX idx_asset_software_asset ON asset_software(asset_id, id)",
        "CREATE INDEX idx_asset_cves_state ON asset_cve_assessments(status, asset_id)",
        "CREATE INDEX idx_asset_cves_cve ON asset_cve_assessments(cve_id)",
        "CREATE INDEX idx_asset_cves_software ON asset_cve_assessments(software_id)",
        "CREATE INDEX idx_asset_events_assessment ON asset_assessment_events(assessment_id, id)",
        "CREATE INDEX idx_asset_import_expiry ON asset_import_previews(expires_at)",
    ]
    # Do not use executescript: it implicitly commits the caller's transaction.
    for sql in statements:
        conn.execute(sql)
    conn.execute("INSERT INTO schema_migrations(version,name) VALUES (1,'asset_prioritization')")
