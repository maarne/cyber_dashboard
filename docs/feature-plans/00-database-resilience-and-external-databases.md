# Database resilience and external database installation

**Status:** implementation approved. Stage A (durable SQLite and recovery safeguards) is implemented; Stages B–F remain pending. No live database adoption or deployment has been performed. See [current operations](../storage-resilience.md) and [validation](../storage-resilience-validation.md).
**Priority:** foundational reliability work, recommended before roadmap Features 4–5.
**Goal:** retain an embedded SQLite option while supporting PostgreSQL and MariaDB,
with a secure first-install selector and environment-based unattended configuration.

## 1. Outcome and boundaries

The installer will offer:

| Choice | Intended use | Durable state requirement |
| --- | --- | --- |
| **SQLite — local file** | Simplest single-server installation; no DB server needed | A persistent host directory or Docker volume, plus backups |
| **PostgreSQL — external server** | Existing/self-hosted database with server-managed durability | Reachable provisioned database, credentials, appropriate TLS and backups |
| **MariaDB — external server** | Existing/self-hosted database with server-managed durability | Reachable provisioned InnoDB database, credentials, appropriate TLS and backups |

All three are SQL databases. The current method is specifically **embedded SQLite**,
not a separate category from SQL. External means a separate database service; it
can run on the same server or another machine, not necessarily in a paid cloud.

On a genuinely new installation, the browser asks which engine to use and, for
an external engine, asks for connection details. Complete environment configuration
skips the database questions. Existing installations retain their current backend.

### Include

- Durable configuration and signing-key handling, not just durable application data.
- No silent empty-DB replacement or fallback when a configured DB disappears/fails.
- A database-independent bootstrap/setup state machine and safe database testing.
- Backend-neutral data access, migrations, transactions and concurrency behavior.
- Verified SQLite-to-external data migration and documented backup/restore paths.
- Docker/Compose and host-service examples, diagnostics, and a three-engine test matrix.

### Exclude

- Implementing Features 4 or 5, Redis/Celery, an ORM/domain-model rewrite, or HA clusters.
- Automatic creation of cloud databases, paid storage, users on a DB server, or billing accounts.
- Seamless live database switching, dual writes, replication or zero-downtime cutover.
- Blanket support for every SQL engine. MySQL 8.4 can be a follow-up with its own
  test gate; MariaDB compatibility does **not** establish MySQL compatibility.
- Claiming to recover the missing temporary database without a surviving copy.

## 2. Incident and current-code findings

The old port-8765 runtime files were under `/tmp/opencode/...`; that recorded
directory was absent after reboot. Temporary directories are not a durable home
for a database, its settings, signing key, or its only backup. This does **not**
establish that every database copy on the server is gone: a workspace-root
`cyber_dashboard.db` was also observed, but has not been established as the same
runtime dataset. Do not overwrite, migrate or launch it as a substitute without
read-only identification and operator confirmation.

Relevant implementation constraints:

| Location | Current behavior / required change |
| --- | --- |
| `app/config.py` | Resolves `DATABASE_PATH` and requires `JWT_SECRET_KEY` at import; cannot currently render a storage/signing-key setup wizard first |
| `app/database.py` | `sqlite3` connections, automatic directory/file creation, `PRAGMA`, `BEGIN IMMEDIATE`, inline schema creation and startup seeding |
| `app/main.py` | Startup initializes the DB before serving; setup middleware queries the `users` table before deciding whether setup is needed |
| `app/templates/setup.html` | Administrator setup only; needs an earlier storage step |
| `app/migrations.py`, `app/network_migrations.py`, `app/case_migrations.py`, `app/rule_migrations.py` | SQLite DDL/introspection; migration ledger currently versions 1–4 |
| `app/services/` | Raw SQL placeholders, SQLite upserts/date functions, `lastrowid`, SQLite exception types and global-write-lock assumptions |
| `app/services/audit_service.py` | Reads chain head under SQLite writer exclusion; external databases require explicit serialization |
| Scheduler/network/validation services | Shared DB leases, quotas and capacity claims must remain correct across two workers |
| `scripts/backup_database.py` | Consistent, non-overwriting SQLite backup utility; not an external DB backup tool |
| `Dockerfile` | Defaults DB path to `/app/data/...`, but creating the directory does not mount persistent storage |
| `infra/modules/appservice.bicep` | F1 configuration explicitly controls container storage; cannot promise persistence merely from the file path |

**Conclusion:** changing the URL/driver alone is insufficient and risks audit-chain
forks, lost updates, incompatible DDL and data loss. Preserve current security and
feature contracts during a staged portability refactor.

## 3. Durable state layout and lost-database protection

Introduce a documented `APP_DATA_DIR` for installation state:

- System-service example: `/var/lib/cyberdash`, owned by its service user.
- User-service example: `$XDG_DATA_HOME/cyberdash` or `~/.local/share/cyberdash`.
- Docker: `/app/data` **mounted to a named volume or host directory**.
- Existing explicitly configured `DATABASE_PATH`: keep it; never silently move it.
- Development/test temporary storage: explicit disposable mode, never the production default.

Within that directory, keep a versioned private installation manifest, protected
secret files if locally managed, and SQLite data when selected. Directory mode
0700 and files 0600; atomic same-directory write + fsync + rename + directory fsync.
Do not place any of these under served static paths or the image source tree.

The manifest records nonsecret configuration provenance, backend selection, a
database identity UUID, installation completion and configuration generation.
The database records its own identity/schema/setup status. These let startup
distinguish a new installation from an accidentally empty or wrong target.

Rules:

1. `/tmp`, `/run`, in-memory SQLite and obvious container-layer paths are refused
   for normal durable SQLite setup, unless explicitly opted into **disposable mode**.
2. Report the resolved path and deployment persistence declaration. Mount checks
   are best-effort evidence, not proof a storage device or backup will survive failure.
3. After installation, open SQLite in existing-file mode. If missing, report
   `database_missing`; **do not create a new file, reseed, or reopen public setup**.
4. For external DBs, unavailable/wrong/empty targets produce recovery/unavailable
   states, not fallback SQLite or a new administrator registration page.
5. Stateless external deployments should set `EXPECTED_DATABASE_ID` after initial
   provisioning, or retain the installation manifest in persistent storage.
   Initial schema creation always requires an explicit installer/init action.
6. SQLite volume/database restore must agree with the installation identity;
   mismatch requires explicit operator recovery, not automatic adoption.
7. If *all* local state and identity pinning are lost, software cannot infer a prior
   installation from nothing. Protect bootstrap behind operator authentication,
   require explicit new-install consent, and explain this limitation honestly.

Existing installations without a manifest get a non-destructive adoption path:
inspect the existing schema, preserve accounts/history and path, back up, then
record identity/manifest. Finding more than one plausible file requires a decision;
never select by newest timestamp alone. Absence is not permission to initialize.

### Signing key and configuration resilience

- Support `JWT_SECRET_KEY` and `JWT_SECRET_KEY_FILE`; retain current secret validation.
- In wizard-managed installations, generate a random key only during explicit new
  installation and save it durably **before** issuing real authentication sessions.
- Never automatically replace a missing production key. Restore it or require a
  deliberate rotation with documented session invalidation and recovery effects.
- External DB storage does not eliminate the need to preserve connection settings,
  CA files, signing keys, feature flags and operator-held audit checkpoints.
- Environment/secret-file-managed installations need no writable local secret store;
  their deployment configuration is the durable source of truth.

## 4. Configuration contract

Names below describe the full initiative. Stage A currently supports `APP_DATA_DIR`,
`DATABASE_PATH`, `JWT_SECRET_KEY_FILE`, `EXPECTED_DATABASE_ID` and
`ALLOW_EPHEMERAL_STORAGE` plus the existing signing-key setting. External DB,
installer-token and pool/migration settings remain design targets, not enabled options.

| Setting | Purpose |
| --- | --- |
| `APP_DATA_DIR` | Durable installation directory |
| `DATABASE_URL` / `DATABASE_URL_FILE` | Complete backend URL, or secret file containing it |
| `DB_TYPE` | `sqlite`, `postgresql`, or `mariadb` when using structured settings |
| `DATABASE_PATH` | Existing SQLite-path setting, retained for compatibility |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` | External connection parameters |
| `DB_PASSWORD` / `DB_PASSWORD_FILE` | External password; secret-file form recommended |
| `DB_TLS_MODE` | Normalized `verify-full` default for TCP; maps to each driver's real settings |
| `DB_TLS_CA_FILE` | Operator-mounted trust root; optional client-cert/key files for approved mutual TLS |
| `DB_CONNECT_TIMEOUT_SECONDS` | Bounded initial connection timeout; proposed 5 seconds |
| `DB_POOL_SIZE`, `DB_POOL_MAX_OVERFLOW` | Conservative per-process limits; proposed 2 and 0 |
| `DB_POOL_TIMEOUT_SECONDS` | Bounded pool wait; proposed 5 seconds |
| `EXPECTED_DATABASE_ID` | Pin the intended existing data store in environment-managed deployments |
| `DB_AUTO_MIGRATE` | Optional serialized known-schema upgrades; default false in production |
| `SETUP_TOKEN` / `SETUP_TOKEN_FILE` | Operator bootstrap authorization, not a DB password or account password |
| `JWT_SECRET_KEY` / `JWT_SECRET_KEY_FILE` | Stable application signing secret |
| `ALLOW_EPHEMERAL_STORAGE` | Explicit disposable/test override, false by default |

### Resolution and precedence

1. Treat a URL and the structured external connection fields as **alternative
   complete configuration groups**. Do not assemble one connection from partial
   credentials belonging to different groups or installation files.
2. Explicit environment configuration wins over a wizard-managed profile as a
   whole; the UI labels it environment-managed and does not edit or reveal it.
3. Within the environment, URL/value and corresponding `_FILE` together are a
   configuration error. A URL plus structured external fields, contradictory
   `DB_TYPE`, or partial external configuration also fails with a sanitized error.
4. `DATABASE_URL` for an external engine supersedes the old image's default
   `DATABASE_PATH`; report the unused SQLite setting without connecting to it.
   Remove the baked-in `DATABASE_PATH` default in the updated image so an
   unconfigured new container can actually show the backend selector.
5. If no environment group exists, use the installed profile; otherwise a confirmed
   legacy SQLite configuration is adopted, or a genuinely new install shows setup.
6. Empty supplied values count as invalid explicit configuration, not as absence.
7. Backend/parser/driver allowlists are fixed. Reject arbitrary driver imports,
   unsupported URL query arguments, multi-host URLs and path interpolation tricks.
8. Construct URLs from structured fields using the library's URL builder, not
   string concatenation. Passwords containing `@`, `:`, `/`, `%` and Unicode must work.
9. Shared TLS/pool options may accompany either connection representation, but
   contradictory URL and dedicated TLS options are rejected. A structured SQLite
   selection accepts only SQLite-relevant options; external credentials cannot leak
   into an embedded profile.

Complete database environment configuration skips **database selection and credential
entry**, not necessarily first-admin creation. Fully unattended provisioning needs
an explicit schema-init command and a separate protected administrator-provisioning
mechanism; never ship a default admin/password or infer consent from credentials.

## 5. First-install experience and bootstrap security

### Bootstrap states

`storage_unconfigured → storage_tested → initialization_pending → admin_required → ready`

Separate failure states: `configuration_invalid`, `database_unavailable`,
`database_missing`, `database_identity_mismatch`, `schema_upgrade_required`,
`initialization_incomplete`. A connectivity error must never mean “no admin exists.”

Bootstrap code must run without importing database-dependent auth/settings helpers
or requiring the final application signing key. Pause feed refresh, asset jobs,
validators and all ordinary data routes until storage/schema/admin state is ready.
Normal RBAC, CSRF and signing-key checks remain mandatory once the app is operational.

### Wizard sequence

1. **Authorize installation.** Use a high-entropy operator setup token from a secret
   file/environment or a local CLI enrollment command. Do not allow “first visitor
   becomes administrator.” Exchange the token in a POST for a short-lived protected
   setup session; do not put it in a URL, access log or localStorage.
2. **Choose storage.** Radio options: SQLite, PostgreSQL, MariaDB. Explain local
   persistence versus external service responsibility and show configuration provenance.
   With complete env configuration, skip editable DB steps and show only a masked status.
3. **Enter connection details.** SQLite: durable directory/file path. External:
   engine, host, port (5432/3306 defaults), database, username, password, TLS mode/CA.
   Explain that the database must already be created; no server-root credential needed.
4. **Test connection.** Explicit bounded POST. Verify native protocol, selected
   engine/version, TLS policy, expected schema/identity and read access. Plain testing
   must not create tables or modify another application's database. Show sanitized
   failures: DNS/connect timeout, rejected login, certificate failure, wrong engine,
   unsupported schema or insufficient privileges. Never echo driver errors/URLs/passwords.
5. **Initialize or adopt.** For an empty dedicated database, explain required DDL
   rights and ask for explicit initialization consent. Create/upgrade a known
   CyberDash schema under an installer lock. An existing compatible CyberDash DB is
   adopted without reseeding or creating an extra admin. Unknown populated databases
   are refused; do not truncate, merge or drop anything. Incompatible versions need
   a migration/restore decision, not automatic repair.
6. **Persist configuration.** Atomically save a private profile and secret reference,
   or keep the environment source unchanged. Retest persisted configuration, record
   DB identity and checkpoint the installation state. Do not declare success if the
   settings cannot survive restart. Treat DB/config writes as a recoverable sequence,
   not a fictitious transaction spanning SQL and the filesystem.
7. **Create first admin if needed.** Preserve existing password policy and race
   protection. DB credentials and CyberDash user credentials are separate. Mark setup
   complete only after account/config/schema state is consistent; invalidate bootstrap
   sessions/tokens and disable setup mutation endpoints.
8. **Persistence/recovery summary.** Show backend, masked location, configuration
   source, storage caveats, how to back up/restore, and whether any verified backup
   exists. Do not invent a successful backup from a successful connection test.

### Security requirements

- HTTPS for remote setup; local loopback/SSH-tunnel setup may use HTTP with an
  explicit development/local deployment boundary. Never trust spoofed forwarding headers
  to grant local access. Keep setup token authorization even on loopback.
- Setup-specific origin/CSRF protection, request-size/rate/time/concurrency limits,
  no-store responses and no browser/password telemetry or request-body logging.
- Passwords never returned by status APIs or placed in HTML, URLs, exports or logs.
  Hold candidate credentials only for the bounded request or protected short-lived
  setup state; if restart interrupts an unpersisted step, ask for them again.
- Wizard-managed secrets use permission-restricted files outside served paths;
  prefer mounted secrets for containers. Optional encryption requires a separately
  managed master key; do not claim encryption helps if its key is beside the ciphertext.
- Restrict tests to the three native DB adapters, not generic URL/TCP probes. Permit
  intentional private/loopback DB hosts and Docker service names independently of
  asset-probe/webhook scope. Block metadata/link-local/multicast and app HTTP targets;
  validate the actual driver connection target/TLS identity, including DNS changes.
- SQLite path selection is operator-authorized and confined to approved data roots;
  defend against symlink traversal and overwriting arbitrary files.
- A setup/storage reconfiguration attempt after completion is denied. Existing admins
  may view sanitized diagnostics; switching DBs requires maintenance-mode operator tools.

### Multiple workers and interrupted installation

No per-process in-memory “setup complete” flag. Use a durable, versioned bootstrap
manifest and OS file lock on the shared local configuration directory while storage
is unconfigured; use a database installer lock once connected. This first release
supports one application host with two workers, not cross-host wizard coordination.
Workers reload a validated config generation or undergo a coordinated restart;
they must never keep serving different backend profiles after setup.

After a crash, inspect the manifest and database marker to resume/retry safely.
If schema creation succeeded but config persistence failed, retain that database
and give recovery instructions; no second initialization or automatic cleanup/drop.

## 6. Data-access architecture

**Recommendation:** SQLAlchemy 2.x **Core** for connections, schema metadata, query
expressions and dialect-aware operations; Alembic for explicit migrations. Keep
FastAPI/Jinja/vanilla JS, current domain services and synchronous service boundaries.
Do not introduce a full ORM or use regex/string replacement to translate arbitrary SQL.

Proposed drivers: standard-library SQLite, Psycopg 3 for PostgreSQL, and PyMySQL
for MariaDB. Select/pin exact versions and review licenses, TLS behavior, Python
3.11 binary wheels and transitive dependencies during implementation. Driver
extras/optional imports must allow SQLite-only installations without external drivers.

Initial integration targets should include PostgreSQL 16/17 and MariaDB 10.11/11.4,
plus the SQLite library bundled with each supported Python/runtime image. Confirm
vendor support and minimum SQL capabilities when implementation starts, pin exact
CI image versions/digests, and publish the tested matrix. A newer/older engine is
not automatically supported merely because its wire protocol connects.

Introduce a narrow storage package, for example:

```text
app/storage/config.py          # pure parsing, provenance, redaction, identity checks
app/storage/engine.py          # per-process engines/pools, connection lifecycle
app/storage/schema.py          # portable tables, constraints, indexes
app/storage/transactions.py    # read/write scopes, guarded updates, error mapping
app/storage/coordination.py    # audit head, quotas, leases and installer locks
app/storage/dialects/          # small tested backend-specific operations
app/bootstrap/                 # DB-independent installation state and routes
migrations/                   # Alembic environment and reviewed revisions
```

`app/database.py` can remain a transitional facade while services are converted
in tested groups. The external backend is not advertised as usable until **every**
data path has been ported, including disabled-feature migrations, scripts, background
workers, exports, auth and API token throttling. Do not deliver partial support.

Engine ownership is per worker after fork; never share pooled connections across
Gunicorn workers. Use a small bounded pool, pre-ping, bounded connect/statement/lock
waits and backend-appropriate connection recycling. Two workers × pool 2 = up to
4 web connections, **plus** explicitly budgeted installer/maintenance connections.
Background tasks in those processes share their process pool rather than silently
allocating another unbounded pool. Measure before raising limits on F1.

Do not run blocking DB probes/migrations directly on the async event loop. Preserve
bounded thread execution for sync DB access. DB errors become typed sanitized
errors; never convert a failed query into an empty successful catalog/setup result.

## 7. SQL/schema portability work

| Existing assumption | Planned portable behavior |
| --- | --- |
| `?` parameters and `sqlite3.Row` | Bound Core expressions/named parameters; explicit mapping results |
| `sqlite3.IntegrityError` | Application error mapping from driver/SQLAlchemy types; distinguish uniqueness, FK, outage and retryable conflict |
| `lastrowid` / autoincrement | Dialect-supported generated identity retrieval; preserve imported IDs and advance sequences |
| `INSERT OR IGNORE`, `OR REPLACE`, `ON CONFLICT` | Explicit semantic upsert helpers per dialect; never emulate replacement with delete/reinsert |
| `PRAGMA`, inline startup DDL | Schema inspector and reviewed backend-aware migrations |
| `datetime('now')`, SQLite date expressions | Consistent application UTC values or tested portable expressions |
| `CAST(... AS BLOB)` byte quotas | Backend-aware UTF-8 payload byte accounting, not database character counts |
| SQLite global writer exclusion | Explicit row locks/CAS/coordination described below |
| SQLite `LIKE`/sorting/NULL behavior | Defined case/Unicode/escape/null semantics and cross-backend fixtures |

Specific schema decisions must be reviewed before migrations are frozen:

- InnoDB + `utf8mb4` on MariaDB; explicitly defined identifier comparison semantics,
  not an accidental server-default case-insensitive/accent-insensitive collation.
- Bounded indexable strings versus large text. MariaDB index-byte limits, text
  defaults, identifier lengths and composite unique keys need explicit designs.
  Never truncate old values or substitute a prefix-only unique index. Where a
  digest key is necessary, verify the complete value and handle collisions safely.
- MariaDB's ordinary `TEXT` has a smaller byte capacity than SQLite/PostgreSQL text.
  Choose tested `MEDIUMTEXT`/`LONGTEXT` storage where source, evidence or reports can
  exceed it; verify server/client packet limits against the application's existing
  payload caps. Do not silently shrink the 200 KiB rule-source or evidence limits.
- Keep immutable snapshot JSON and hashed audit fields as exact text/bytes; do not
  round-trip through native JSON or timezone normalization that changes historical
  hashes. Preserve original timestamp spelling where it participates in hashes.
- Explicitly preserve boolean/API representations, null-versus-empty values,
  decimal/float serialization, UTF-8 lengths, enum/check constraints and FK actions.
- Circular rule revision/publication/validation references require a two-phase
  nullable FK/import strategy; MariaDB has no deferrable constraints. Do not rely
  on globally disabling FK checks or transactional behavior for all DDL.
- Test nullable unique keys and migration handling of legacy duplicate/collation
  conflicts. Report them; never silently merge accounts, rules or other identities.

## 8. Transactions and multi-worker correctness

Use short transactions and explicit concurrency primitives instead of assuming
SQLite's `BEGIN IMMEDIATE` protects all operations on every backend.

1. **Audit chain:** create a singleton coordination/head row. Acquire its lock
   before reading/updating the chain head, even when the audit table is empty;
   `SELECT FOR UPDATE` on a nonexistent last audit row is not sufficient. Append
   the domain change and audit record in the same transaction. Define one global
   lock acquisition order to avoid deadlocks and preserve external checkpoints.
2. **Optimistic versions:** guarded `UPDATE ... WHERE row_version = expected`
   and checked affected-row semantics, or row locking plus the same check. Preserve
   one success/one 409 for conflicting user edits and rule publication.
3. **Quota/capacity checks:** transactionally lock scoped budget/identity rows before
   count-and-insert. Concurrent snapshot creation must not exceed global storage
   caps just because external DB transactions no longer serialize all writers.
4. **Worker leases/rate limits:** atomic claim/update with unique keys, expiry and
   ownership checks. Persist two rule-validator slots and shared network/refresh
   budgets; test multi-worker start, expiry, crash and duplicate-job races.
5. **First administrator/setup:** lock a pre-existing installation coordination row
   and recheck setup state. No two primary admins from simultaneous bootstrap posts.
6. **Reads/exports:** use defined snapshot/transaction isolation for consistent
   multi-query histories/exports; account for PostgreSQL READ COMMITTED and MariaDB
   isolation differences instead of assuming a single transaction freezes every read.
7. **Retries:** only bounded whole-transaction retries for known safe deadlocks/
   serialization failures, with idempotency where needed. Never replay arbitrary
   mutations after ambiguous connection loss or duplicate external side effects.
8. **Outages:** fail closed for auth, writes, counters and worker ownership. Pause
   jobs and resume under leases after recovery; no fallback DB, fake empty results,
   new setup page or immediate unlimited retry storm.

## 9. Schema migrations and moving existing data

### Schema/version strategy

- Preserve the existing `schema_migrations` 1–4 history. Introduce a reviewed
  portability baseline/bridge to Alembic, with a separate Alembic revision ledger.
  Inspect/verify actual legacy schema before adopting/stamping; do not just stamp
  an unknown database as current. Seed protection and lifecycle activation remain intact.
- Fresh installs create the selected backend through migrations, not ORM
  `create_all` plus opportunistic `ALTER TABLE` in web startup.
- Prefer a dedicated init/migration CLI before web workers start. Wizard-managed
  fresh installation invokes the same coordinator; existing production upgrades
  require an explicit operator step unless approved auto-migrate is enabled.
- Use backend-specific bounded installer locks; one migration leader, other workers
  wait or return not-ready. MariaDB DDL may implicitly commit: journal incomplete
  operations and test resumability; never promise all DDL rolls back atomically.
- Separate migration/DDL privileges from runtime DML privileges where practical.
  Wizard may accept a one-time migration principal without saving it for runtime.
  Do not require server superuser, `CREATE USER`, filesystem or replication privileges.
- Wrong application/schema, nonempty unknown targets and newer unsupported revisions
  are hard stops. Schema rollback means restoring a verified backup, not destructive
  automatic downgrade or reopening old mutable rule APIs.

### SQLite → PostgreSQL/MariaDB cutover

Provide a maintenance CLI, not a publicly accessible migration form:

1. Identify the source **read-only**, verify integrity, record schema/data identity,
   count tables/rows and verify existing audit/snapshot hashes. Resolve any known
   pre-existing integrity warnings with the operator; do not “repair” evidence.
2. Stop all writers/workers, take a consistent source backup, and save an external
   audit checkpoint plus private deployment configuration. Source remains untouched.
3. Test an explicitly empty, dedicated target and its privileges/version/TLS.
   Create schema without seeding. Abort on any unknown/nonempty destination.
4. Copy in bounded batches preserving primary keys, foreign keys, settings,
   accounts/password hashes, session/token state, audit bytes, evidence and rule
   history/publication pointers. Handle FK cycles by documented second-pass links.
5. Verify exact per-table counts, references, canonical values/hashes, lifecycle
   latch, and sequence/identity high-water marks, including deleted-ID history
   where needed to prevent identity reuse. Report any unsupported values/conflicts.
6. Do not carry active execution leases as running ownership onto the target.
   Reconcile leases/jobs in an explicit, documented, audited post-copy step with
   network monitoring/discovery paused until the operator resumes them. Verification
   must distinguish intentional execution-state changes from copied evidence.
7. Switch the configuration/expected identity during the maintenance window;
   preserve the signing key. Run non-mutating readiness checks and controlled
   authentication verification without scans, enrichment or rule publication.
8. Keep the source/backup private and read-only. Before target writes, reverting
   configuration can restore service to the source. After target writes, that
   reversion loses new data; require a deliberate recovery/reconciliation decision.

Cross-engine transfer is not piping a SQLite `.dump` into another server. The first
release needs both SQLite-to-external targets; external-to-external and reverse
transfer can be deferred explicitly rather than advertised as supported.

## 10. Backup, reboot and outage resilience

External databases solve separation from the application container, **not** backup,
accidental deletion, host-disk failure, ransomware or a DB on the same ephemeral disk.

Deliver three runbooks and automated restore tests:

- **SQLite:** retain the existing online-backup API utility with integrity checks,
  private permissions and non-overwriting outputs; configure a durable local copy
  and an independent off-host copy. Do not copy an active DB/WAL blindly.
- **PostgreSQL:** version-compatible native dump/restore procedures, for example
  custom-format `pg_dump` and tested `pg_restore`, with documented transaction scope.
- **MariaDB:** native version-compatible logical dump/restore for transactional
  InnoDB data, with DDL-quiescence/consistency requirements explicitly stated.

Use operator-side native tools or a purpose-built local backup job/container rather
than installing broad DB-admin utilities in the web image. Pass credentials through
protected files/native mechanisms, not command-line arguments. Encrypt and protect
backups since they contain hashes, tokens, internal evidence and configuration.

Proposed initial operating policy: daily database backup; additional backup before
upgrade/migration; seven daily and four weekly retained successful copies; regular
off-host replication and a restore drill at installation and at least monthly.
Operator approval must account for available storage and sensitivity. A once-daily
successful off-host backup implies a target RPO of up to 24 hours, **not** zero
data loss. Measure restore time before committing an RTO. Retention must never delete
the last known-good backup merely because the newest run failed.

On self-hosted Linux, offer a documented systemd timer or operator cron job; do not
rely on the sleeping app process for backups. Do not provision paid schedulers,
paid backup storage or paid DB services. F1 downtime/sleep and lack of direct private
network reachability may make some external DB locations unusable; document that
constraint rather than changing SKUs or opening a DB to the internet automatically.

### Diagnostics

- `/api/health`: process liveness, independent of database connectivity.
- `/api/ready`: bounded storage/schema/setup check; 503 when unusable. Preserve
  compatible existing fields and add nonsecret machine-readable state codes.
- Operator diagnostics: backend/version, masked configuration source, DB identity,
  schema revision, pool/connection status, declared persistence and last **verified**
  backup metadata if integrated. No credentials or internal DB topology in public health.
- Distinguish “backup not configured/unknown” from verified success. Record reconnects,
  failed migrations, lock exhaustion and backup failures without sensitive SQL/URLs.

## 11. Deployment examples and first-run modes

The following are **future configuration examples**, not commands to run against
the current release. Use placeholders and secret files, never committed passwords.

```dotenv
# SQLite: /app/data must be mounted persistently in Docker.
DB_TYPE=sqlite
DATABASE_PATH=/app/data/cyber_dashboard.db
APP_DATA_DIR=/app/data
JWT_SECRET_KEY_FILE=/run/secrets/cyberdash_jwt
```

```dotenv
# External PostgreSQL: DB already exists; complete group skips credential questions.
DB_TYPE=postgresql
DB_HOST=postgres.example.internal
DB_PORT=5432
DB_NAME=cyberdash
DB_USER=cyberdash_app
DB_PASSWORD_FILE=/run/secrets/cyberdash_db_password
DB_TLS_MODE=verify-full
DB_TLS_CA_FILE=/run/secrets/db_ca.pem
JWT_SECRET_KEY_FILE=/run/secrets/cyberdash_jwt
# EXPECTED_DATABASE_ID=<UUID recorded after deliberate initialization>
```

For MariaDB use `DB_TYPE=mariadb`, port 3306 and the corresponding server name;
other fields have the same meaning. Alternatively supply a secret `DATABASE_URL_FILE`
containing an allowlisted `postgresql+psycopg://...` or `mariadb+pymysql://...` URL
with validated TLS policy. Never combine the URL and structured credentials.

Deliver Compose examples for **each** backend: persistent app/config volume for
SQLite/wizard mode; persistent server volume for optional local DB containers;
read-only mounted secrets; database health checks; no published DB ports by default;
least-privilege credentials; and a repeatable init/migrate step. A server container
without a persistent volume has the same class of loss risk as an app container.

Plain `docker compose down` must preserve named data volumes; prominently document
that `down -v`, volume deletion and host disk loss destroy them. Add host-service
restart-on-boot examples and one explicit data path; a durable DB does not itself
restart the application after reboot.

Mode expectations:

| Mode | Behavior |
| --- | --- |
| New interactive, no DB env/profile | Token-protected storage selector, test, consented init, admin step |
| Complete env + compatible installed DB | No DB questions; verify identity/schema and serve/login |
| Complete env + empty DB | No credential questions; require protected explicit init consent or one-off CLI init, then admin provisioning |
| Fully unattended | Explicit operator init/migrate CLI + protected admin provisioning + complete env/secrets; no default accounts |
| Partial/bad env | Sanitized configuration error; do not prompt to override managed secrets or fall back |
| Previously installed DB absent/unreachable | Recovery/unavailable state; never first-time registration |

## 12. Implementation stages and release gates

| Stage | Deliverable | Exit gate |
| --- | --- | --- |
| A. Incident inventory + durable SQLite | Read-only source inventory, durable paths/manifest, fail-closed missing DB, signing-key persistence, mount/service/backup instructions | Reboot and container replacement preserve state; missing DB cannot create a new installation |
| B. Portable storage foundation | Core engine/schema/transactions, error mapping; services converted with SQLite behavior retained | All existing suites pass; no business-layer SQLite-only calls remain unreviewed |
| C. PostgreSQL | Migrations, driver, concurrency/locks, cutover tool and real backend integration | Full contract/security/concurrency/migration/restore matrix passes |
| D. MariaDB | InnoDB schema/collation/index/DDL handling, driver and real backend integration | Same matrix passes independently, including DDL interruption and constraint semantics |
| E. Installer + env/Docker | Bootstrap states, secure wizard, env precedence/secrets, installation locks, Compose examples | Browser and unattended first-run/restart/crash/outage tests pass on all three engines |
| F. Recovery + release | Native backup runbooks/jobs, restore drills, performance/pool budgets, operator documentation | Verified backup/cutover/reboot demos, F1 regression and explicit rollout approval |

These are slices of **one reliability initiative**, not permission to enable an
unfinished backend or start the other roadmap features. Stage A can be released
first to reduce immediate SQLite risk, but this request is complete only when
SQLite, PostgreSQL and MariaDB all meet the installation and data-safety gates.
Do not migrate any existing user database automatically as part of coding/testing.

### Main change map

- New `app/storage/`, `app/bootstrap/`, migration environment and CLI utilities.
- Adapt `app/config.py`, `app/database.py`, `app/main.py`, setup templates/JS,
  health checks, startup ordering and auth bootstrap helpers.
- Port all services and migration/backup/maintenance utilities; retain current
  feature flags, RFC1918-default asset scope, source isolation and RBAC rules.
- Update `Dockerfile`, `.env.example`, README, host-service documentation and new
  Compose examples; any infrastructure changes are configuration-only and F1-only.
- Extend `scratch/` tests and CI with disposable PostgreSQL/MariaDB services and
  migration fixtures. Never reuse a production connection string for tests.

## 13. Acceptance test checklist

### Configuration / setup / secrets

- New SQLite/PG/MariaDB wizard selections; env-only DB setup skips entry; partial,
  empty, conflicting, unreadable `_FILE`, malformed URL and wrong driver cases fail safely.
- Special-character passwords, verified TLS, wrong-host/expired/untrusted certs,
  explicit insecure local-dev opt-in, least-privilege runtime and one-time DDL roles.
- No setup-token guessing/takeover/CSRF, public DB probes, path traversal, password
  echoes, leaked URLs/SQL, or secret values in logs/browser storage/status/exports.
- Restart at every wizard checkpoint; unwritable config, two-worker races, stale
  config generations, init interruption and unknown populated targets preserve data.
- Existing-admin adoption never creates another first admin. Missing DB/key and
  external outages never enable registration or generate replacements.
- Connection success is not proof of DDL/DML privileges: read-only testing reports
  what was actually verified, and initialization/runtime permission checks fail
  clearly at their explicit, consented step.

### Behavior / migration / concurrency

- Full existing feature/security suites on **real** SQLite, PostgreSQL and MariaDB;
  mocks or SQLite do not establish external support. Run all feature-flag combinations.
- New installs and representative legacy schemas through versions 1–4; repeated
  startup, partial failed migrations, newer unsupported schema and no silent reseeding.
- Exact account IDs/hashes, audit chain/checkpoints, snapshot JSON/hashes, timestamps,
  case references, rule visibility/latch, archived data and deleted-ID high-water marks.
- Concurrent auth setup, audit appends including empty ledger, token throttling,
  revisions/publications, quota writes, job/slot claims and lease recovery.
- Text/Unicode/collation/NULL/upsert/byte-quota differences, oversized/indexed fields,
  invalid constraints, and sequence continuation after import.
- DB disconnect during writes, ambiguous commit, deadlock, serialization conflict,
  pool exhaustion and bounded retries produce truthful errors without duplicate effects.
- Export snapshots remain consistent during concurrent mutations on each backend.

### Persistence / operations

- Synthetic populated dataset survives host reboot, service restart, image rebuild,
  app-container replacement and DB-container replacement with mounted volumes.
- Remove/rename a SQLite file or point at an empty/wrong external DB: readiness
  fails, prior installation stays locked, no fresh DB/account appears.
- Restore each engine into an isolated destination, verify rows/hashes/checkpoints,
  and measure recovery time. Confirm incomplete/failed backups do not replace a
  good copy and secrets/private restore paths do not leak.
- Two-worker query/pool/CPU/RAM/lock budgets measured with realistic CVE, asset,
  case and rule data. No claim of durability or uptime from a passing smoke test alone.
- F1-only infrastructure guards remain intact; no paid services, automatic DB
  port exposure, real scans, live enrichment, or real rule publication during tests.

## 14. Recommended decisions for approval

1. **Support SQLite, PostgreSQL and MariaDB** as the initial engines; develop PG
   first, but do not call the initiative complete before MariaDB parity.
2. **Use Core + Alembic**, not a whole-app ORM rewrite or a raw-SQL translation shim.
3. **Secure the installer with an operator token**, with database configuration
   preceding administrator creation and environment values locking their UI fields.
4. **Keep SQLite easy but durable**: persistent data directory/volume, an installation
   identity and explicit disposable-mode opt-in; no runtime or backups in `/tmp`.
5. **Fail closed** on missing/unreachable/wrong storage; no fallback, automatic
   reinstallation or silent signing-key replacement.
6. **Prefer verified TLS and least privilege**; permit insecure local development
   only by explicit, prominently labeled opt-in, not an automatic downgrade.
7. **Use maintenance-window migration** with an untouched source, verified target,
   clear rollback boundary and backup/restore rehearsal.
8. **Keep external infrastructure operator-supplied** and all current F1 guards.
   Choose backup location/retention and whether any existing DB is recoverable
   before a rollout; those cannot be inferred safely from this plan.

**Next action:** complete the portable SQL layer (Stage B), then the separately
validated external adapters and installer. Stage A is delivered with explicit
operator commands; choosing/adopting a surviving live database and enabling host
services/backups still require the operator's recovery/deployment decision.
