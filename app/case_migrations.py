"""Additive case/evidence schema; legacy investigations keep unknown attribution."""


def apply_case_migration(conn):
    if conn.execute('SELECT 1 FROM schema_migrations WHERE version=3').fetchone():
        return
    actor = '''actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        actor_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL, actor_name TEXT NOT NULL'''
    statements = [
        f'''CREATE TABLE cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT UNIQUE,
            title TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','closed')),
            assignee_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            {actor}, conclusion TEXT CHECK(conclusion IN ('malicious','benign','security_test','inconclusive')),
            closure_reason TEXT, closed_at TEXT, is_archived INTEGER NOT NULL DEFAULT 0 CHECK(is_archived IN (0,1)),
            row_version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            CHECK((status='closed' AND conclusion IS NOT NULL AND length(closure_reason)>0 AND closed_at IS NOT NULL)
               OR (status!='closed' AND conclusion IS NULL AND closure_reason IS NULL AND closed_at IS NULL)))''',
        f'''CREATE TABLE investigation_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT NOT NULL, indicator_type TEXT NOT NULL,
            principal_key TEXT NOT NULL, {actor}, captured_at TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1, payload_json TEXT NOT NULL,
            sha256 TEXT NOT NULL, payload_bytes INTEGER NOT NULL CHECK(payload_bytes BETWEEN 1 AND 262144))''',
        f'''CREATE TABLE case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id),
            body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 8000), {actor},
            supersedes_note_id INTEGER REFERENCES case_notes(id), created_at TEXT NOT NULL)''',
        f'''CREATE TABLE case_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id),
            snapshot_id INTEGER NOT NULL REFERENCES investigation_snapshots(id), {actor},
            created_at TEXT NOT NULL, UNIQUE(case_id,snapshot_id))''',
        f'''CREATE TABLE case_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id),
            kind TEXT NOT NULL CHECK(kind IN ('asset','cve','actor','rule')), target_id TEXT NOT NULL,
            label TEXT NOT NULL, {actor}, created_at TEXT NOT NULL, UNIQUE(case_id,kind,target_id))''',
        f'''CREATE TABLE case_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id),
            kind TEXT NOT NULL, {actor}, payload_json TEXT NOT NULL,
            audit_event_id INTEGER NOT NULL REFERENCES audit_logs(id), created_at TEXT NOT NULL)''',
        'CREATE INDEX idx_cases_status ON cases(is_archived,status,updated_at,id)',
        'CREATE INDEX idx_cases_assignee ON cases(assignee_user_id,status,id)',
        'CREATE INDEX idx_snapshots_indicator ON investigation_snapshots(indicator,id)',
        'CREATE INDEX idx_snapshots_principal ON investigation_snapshots(principal_key,id)',
        'CREATE INDEX idx_case_evidence_snapshot ON case_evidence(snapshot_id,case_id)',
        'CREATE INDEX idx_case_notes ON case_notes(case_id,id)',
        'CREATE INDEX idx_case_events ON case_events(case_id,id)',
        'CREATE INDEX idx_case_references ON case_references(kind,target_id,case_id)',
    ]
    for statement in statements:
        conn.execute(statement)
    for column, definition in (
        ('actor_user_id', 'INTEGER REFERENCES users(id) ON DELETE SET NULL'),
        ('actor_token_id', 'INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL'),
        ('actor_name', 'TEXT'),
        ('snapshot_id', 'INTEGER REFERENCES investigation_snapshots(id)'),
    ):
        conn.execute(f'ALTER TABLE investigation_history ADD COLUMN {column} {definition}')
    conn.execute("INSERT INTO schema_migrations(version,name) VALUES (3,'investigation_case_management')")
