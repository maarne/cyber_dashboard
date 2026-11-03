"""Additive schema and exact legacy snapshots; activation is a persistent safety latch."""
import hashlib
import json

FIELDS = ('title', 'rule_type', 'mitre_ttp', 'severity', 'target_cve', 'description', 'code_content', 'target_siem', 'deployment_guide')


def manage_existing(conn):
    conn.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES ('rule_lifecycle_activated','true')")
    rows = conn.execute('SELECT * FROM detection_rules WHERE lifecycle_managed=0 ORDER BY id').fetchall()
    for row in rows:
        payload = json.dumps({k: row[k] for k in FIELDS}, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        revision_id = conn.execute('''INSERT INTO rule_revisions(rule_id,revision_number,snapshot_json,sha256,payload_bytes,
            author_key,author_name,state,created_at) VALUES (?,1,?,?,?,'legacy:unknown','Unknown (legacy)','legacy_unreviewed',?)''',
            (row['id'], payload, hashlib.sha256(payload.encode()).hexdigest(), len(payload.encode()), row['created_at'])).lastrowid
        conn.execute('UPDATE detection_rules SET lifecycle_managed=1,working_revision_id=?,published_revision_id=? WHERE id=?',
                     (revision_id, revision_id, row['id']))


def apply_rule_migration(conn):
    if not conn.execute('SELECT 1 FROM schema_migrations WHERE version=4').fetchone():
        actor = '''actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL, actor_name TEXT NOT NULL'''
        statements = [
            '''CREATE TABLE rule_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL REFERENCES detection_rules(id),
                revision_number INTEGER NOT NULL, parent_revision_id INTEGER REFERENCES rule_revisions(id),
                snapshot_json TEXT NOT NULL, sha256 TEXT NOT NULL, payload_bytes INTEGER NOT NULL,
                author_key TEXT NOT NULL, author_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                author_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL, author_name TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('legacy_unreviewed','draft','in_review','approved','rejected','published','withdrawn')),
                submitted_validation_id INTEGER REFERENCES rule_validation_runs(id), created_at TEXT NOT NULL,
                UNIQUE(rule_id,revision_number))''',
            f'''CREATE TABLE rule_validation_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, revision_id INTEGER NOT NULL REFERENCES rule_revisions(id),
                revision_hash TEXT NOT NULL, validator_version TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('valid','invalid','error')),
                report_json TEXT NOT NULL, duration_ms REAL NOT NULL, {actor}, created_at TEXT NOT NULL)''',
            '''CREATE TABLE rule_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT, revision_id INTEGER NOT NULL REFERENCES rule_revisions(id),
                validation_id INTEGER NOT NULL REFERENCES rule_validation_runs(id), revision_hash TEXT NOT NULL,
                reviewer_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, reviewer_key TEXT NOT NULL,
                reviewer_name TEXT NOT NULL, decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
                reason TEXT NOT NULL, created_at TEXT NOT NULL)''',
            f'''CREATE TABLE rule_lifecycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL REFERENCES detection_rules(id),
                revision_id INTEGER REFERENCES rule_revisions(id), kind TEXT NOT NULL, {actor},
                details_json TEXT NOT NULL, audit_event_id INTEGER NOT NULL REFERENCES audit_logs(id), created_at TEXT NOT NULL)''',
            '''CREATE TABLE rule_validation_claims (
                slot INTEGER PRIMARY KEY CHECK(slot IN (1,2)), revision_id INTEGER NOT NULL UNIQUE REFERENCES rule_revisions(id),
                owner TEXT NOT NULL, expires_at REAL NOT NULL)''',
            'CREATE INDEX idx_rule_revisions ON rule_revisions(rule_id,id DESC)',
            'CREATE INDEX idx_rule_validations ON rule_validation_runs(revision_id,id DESC)',
            'CREATE INDEX idx_rule_reviews ON rule_reviews(revision_id,id DESC)',
            'CREATE INDEX idx_rule_events ON rule_lifecycle_events(rule_id,id DESC)',
        ]
        for sql in statements:
            conn.execute(sql)
        for name, definition in (
            ('lifecycle_managed', 'INTEGER NOT NULL DEFAULT 0 CHECK(lifecycle_managed IN (0,1))'),
            ('working_revision_id', 'INTEGER REFERENCES rule_revisions(id)'),
            ('published_revision_id', 'INTEGER REFERENCES rule_revisions(id)'),
            ('is_archived', 'INTEGER NOT NULL DEFAULT 0 CHECK(is_archived IN (0,1))'),
            ('row_version', 'INTEGER NOT NULL DEFAULT 1'),
        ):
            conn.execute(f'ALTER TABLE detection_rules ADD COLUMN {name} {definition}')
        conn.execute("INSERT INTO schema_migrations(version,name) VALUES (4,'detection_rule_lifecycle')")
    from app import config
    if config.FEATURE_RULE_LIFECYCLE:
        manage_existing(conn)
