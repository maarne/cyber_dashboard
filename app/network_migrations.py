"""Additive monitoring/discovery schema; never creates targets or jobs."""


def apply_network_migration(conn):
    if conn.execute("SELECT 1 FROM schema_migrations WHERE version=2").fetchone():
        return
    statements = [
        """CREATE TABLE asset_monitor_configs (
            asset_id INTEGER PRIMARY KEY REFERENCES assets(id), settings_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
            generation INTEGER NOT NULL DEFAULT 1, row_version INTEGER NOT NULL DEFAULT 1,
            next_due REAL, last_request REAL, state_json TEXT NOT NULL DEFAULT '{}',
            updated_by TEXT NOT NULL, updated_at REAL NOT NULL)""",
        """CREATE TABLE asset_discovery_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, settings_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
            generation INTEGER NOT NULL DEFAULT 1, row_version INTEGER NOT NULL DEFAULT 1,
            next_due REAL, last_request REAL, cursor INTEGER NOT NULL DEFAULT 0,
            updated_by TEXT NOT NULL, updated_at REAL NOT NULL)""",
        """CREATE TABLE asset_network_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL CHECK(kind IN ('monitor','discovery')),
            asset_id INTEGER REFERENCES assets(id), profile_id INTEGER REFERENCES asset_discovery_profiles(id),
            generation INTEGER NOT NULL, config_json TEXT NOT NULL, policy_hash TEXT NOT NULL,
            actor_json TEXT NOT NULL, source TEXT NOT NULL CHECK(source IN ('manual','scheduled')),
            status TEXT NOT NULL CHECK(status IN ('queued','running','completed','partial','cancelled','error')),
            idempotency_key TEXT, owner TEXT, lease_until REAL,
            due_at REAL NOT NULL, available_at REAL NOT NULL, started_at REAL, completed_at REAL,
            processed INTEGER NOT NULL DEFAULT 0, responding INTEGER NOT NULL DEFAULT 0,
            skipped_periods INTEGER NOT NULL DEFAULT 0, cursor INTEGER NOT NULL DEFAULT 0,
            result_json TEXT NOT NULL DEFAULT '{}', created_at REAL NOT NULL,
            CHECK((kind='monitor' AND asset_id IS NOT NULL AND profile_id IS NULL)
               OR (kind='discovery' AND profile_id IS NOT NULL AND asset_id IS NULL)))""",
        "CREATE UNIQUE INDEX idx_network_active_monitor ON asset_network_jobs(asset_id) WHERE kind='monitor' AND status IN ('queued','running')",
        "CREATE UNIQUE INDEX idx_network_active_profile ON asset_network_jobs(profile_id) WHERE kind='discovery' AND status IN ('queued','running')",
        "CREATE INDEX idx_network_due ON asset_network_jobs(status,available_at,kind)",
        "CREATE INDEX idx_network_asset_history ON asset_network_jobs(asset_id,id DESC)",
        "CREATE INDEX idx_network_profile_history ON asset_network_jobs(profile_id,id DESC)",
        """CREATE TABLE asset_network_locks (
            address TEXT PRIMARY KEY, owner TEXT NOT NULL, expires_at REAL NOT NULL)""",
        """CREATE TABLE asset_network_budget (
            kind TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL,
            PRIMARY KEY(kind,window))""",
        """CREATE TABLE asset_discovery_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, address TEXT NOT NULL,
            hostname TEXT, names_json TEXT NOT NULL DEFAULT '[]', evidence TEXT NOT NULL,
            first_seen REAL NOT NULL, last_seen REAL NOT NULL,
            identity_version INTEGER NOT NULL DEFAULT 1, row_version INTEGER NOT NULL DEFAULT 1,
            is_ignored INTEGER NOT NULL DEFAULT 0 CHECK(is_ignored IN (0,1)),
            needs_review INTEGER NOT NULL DEFAULT 0 CHECK(needs_review IN (0,1)),
            imported_asset_id INTEGER REFERENCES assets(id), UNIQUE(scope,address))""",
        "CREATE INDEX idx_discovery_review ON asset_discovery_candidates(is_ignored,last_seen DESC)",
        """CREATE TABLE asset_discovery_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id INTEGER NOT NULL REFERENCES asset_discovery_candidates(id) ON DELETE CASCADE,
            job_id INTEGER REFERENCES asset_network_jobs(id) ON DELETE SET NULL,
            profile_id INTEGER REFERENCES asset_discovery_profiles(id),
            observed_at REAL NOT NULL, snapshot_json TEXT NOT NULL, snapshot_hash TEXT NOT NULL)""",
        "CREATE INDEX idx_discovery_observation ON asset_discovery_observations(candidate_id,id DESC)",
        "CREATE INDEX idx_discovery_observation_profile ON asset_discovery_observations(profile_id,candidate_id)",
        """CREATE TABLE asset_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL REFERENCES assets(id),
            address TEXT NOT NULL, hostname TEXT, scope TEXT NOT NULL,
            observed_at REAL NOT NULL, provenance_json TEXT NOT NULL, created_by TEXT NOT NULL,
            UNIQUE(asset_id,address,scope))""",
        "CREATE INDEX idx_asset_address_match ON asset_addresses(address,scope)",
        """CREATE TABLE asset_discovery_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL REFERENCES assets(id),
            candidate_id INTEGER REFERENCES asset_discovery_candidates(id) ON DELETE SET NULL,
            observation_id INTEGER REFERENCES asset_discovery_observations(id) ON DELETE SET NULL,
            snapshot_json TEXT NOT NULL, snapshot_hash TEXT NOT NULL, imported_at REAL NOT NULL,
            imported_by TEXT NOT NULL, UNIQUE(asset_id,snapshot_hash))""",
        "CREATE INDEX idx_asset_discovery_links ON asset_discovery_links(asset_id,id DESC)",
        """CREATE TABLE asset_discovery_import_previews (
            token_hash TEXT PRIMARY KEY, actor_key TEXT NOT NULL, inventory_revision INTEGER NOT NULL,
            payload_json TEXT, payload_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
            expires_at REAL NOT NULL, consumed_at REAL)""",
    ]
    for statement in statements:
        conn.execute(statement)
    conn.execute("INSERT INTO schema_migrations(version,name) VALUES (2,'asset_network_monitoring_discovery')")
