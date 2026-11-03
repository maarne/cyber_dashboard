# Storage resilience — Stage A

The approved reliability initiative is being delivered in stages. **Stage A is
implemented:** explicit SQLite initialization/adoption, durable installation state,
identity checks, stable signing-key files, fail-closed recovery and private backups.
PostgreSQL, MariaDB, SQLAlchemy/Alembic conversion and the database-selection wizard
remain later stages; this is **not** full external-database support.

No existing user database was adopted, migrated or replaced during implementation.
The workspace candidate was inventoried read-only: integrity OK, migration version
1, one user, 420 CVEs, no assets, 18 rules. It is older/smaller than the lost 8765
runtime. It remains untouched; operator identification/confirmation is necessary.

## What changed

- Default state now belongs in a durable per-user data directory, not the project
  root or `/tmp`. `APP_DATA_DIR` selects it; existing explicit paths can be adopted.
- `installation.json` records the database path/UUID, schema table inventory,
  initialization state, signing-key reference, and selected nonsecret settings.
  A separate DB identity row also records whether administrator setup completed.
- Ordinary connections use SQLite `mode=rw`: an absent file cannot be created by
  a read, authentication check, health probe or background worker.
- Durable startup verifies identity/schema, instead of silently initializing,
  repairing or reseeding. Explicit rule-lifecycle flag activation still captures
  exact legacy snapshots and preserves its existing safety latch.
- Missing/wrong/empty DBs, missing tables, incomplete installation or a disappeared
  administrator return not-ready/recovery states and do not enable registration.
  Liveness remains available when storage is blocked. Missing/invalid signing keys
  or malformed configuration fail safely at startup rather than generating a new key.
- The old `reset_admin_setup.py` deletion helper is retired: deleting accounts to
  reopen public setup is not a safe recovery method.
- Private file writes use atomic rename/fsync, private permissions and installation
  locking. Temporary/symlink paths and unmounted Docker storage are refused unless
  deliberately marked disposable. Mount detection is best effort, not a guarantee
  against device failure, filesystem loss or administrator deletion.

## New installation — only when you intend to create a new database

Example as a normal local user:

```bash
export APP_DATA_DIR="$HOME/.local/share/cyberdash"
python -B -m scripts.configure_storage init --data-dir "$APP_DATA_DIR" --confirm-new
python -B -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

The command refuses an existing database/profile. If no signing-key source is
provided, it creates a random `signing.key` in that directory, never prints it,
and records its path. Otherwise choose **one** of `JWT_SECRET_KEY` or
`JWT_SECRET_KEY_FILE` before provisioning. Environment keys are not copied into
the profile and must be supplied on subsequent starts from durable deployment
configuration. Secret files must exist at stable absolute paths; an empty explicit
value is not a request to use a fallback. Files containing secrets must not be committed.

Selected feature/network flags, origin and rates present during provisioning are
saved as nonsecret defaults. Explicit environment values override them. An explicit
empty `ASSET_PROBE_ALLOWED_CIDRS` remains deny-all; absent scope still defaults to
RFC1918. Provider secrets are **not** copied into the profile; keep them in protected
service/secret configuration. Use absolute paths and private ownership (directory
0700, configuration/key/DB 0600).

Complete the existing first-administrator wizard over loopback/SSH tunneling before
exposing the app publicly. The operator-token-protected multi-backend web installer
is **Stage E**, not part of Stage A; there are still no default accounts/passwords.

## Existing installation / surviving DB: inspect, then explicitly adopt

Stop every writer, including background/reload workers. Identify the correct source:

```bash
python -B -m scripts.configure_storage inspect --database /absolute/path/existing.db
```

Inspection is read-only and does not import/start the app. It reports schema
versions, identity if present and limited row counts, not usernames, hashes or
credentials. Do not choose among possible files just by modification time.

When the correct source and original signing key have been identified:

```bash
export JWT_SECRET_KEY_FILE=/secure/original-signing-key
python -B -m scripts.configure_storage adopt --data-dir /private/durable/cyberdash --database /absolute/path/existing.db --confirm-adopt
```

Adoption refuses unknown databases and unsupported schema versions, requires a
supplied existing signing key, and takes a private consistent pre-adoption backup
under the installation directory before applying known additive migrations and
recording identity. It skips intelligence seeding and rule title cleanup. Existing
accounts, hashes, evidence, rule IDs/content and other records are retained.
An existing key cannot be proven historically correct from the DB alone; the
operator must supply the original. If it is lost, do not pretend the new install
key is equivalent: arrange an explicit recovery/key-rotation decision separately.

The pre-adoption copy is a safety checkpoint on the same host, **not** a complete
backup strategy. Copy it off-host and save settings/key references. The command
does not move the source file or choose it as the live runtime automatically.
Set `APP_DATA_DIR` for the adopted profile, retain any environment-managed secrets,
start on loopback, and check readiness and authenticated data before exposing it.

## Status, recovery, and interrupted configuration

```bash
python -B -m scripts.configure_storage status --data-dir /private/durable/cyberdash
```

Public `/api/health` remains a process-liveness check. `/api/ready` returns 503 with
a nonsecret code such as `database_missing`, `database_identity_mismatch`,
`schema_incomplete`, `initialization_incomplete`, `schema_upgrade_required` or
`administrator_recovery_required`; no database is created in response. Missing
configuration needs operator initialization/adoption, never a browser registration
shortcut. Startup-blocked instances require restart after recovery.

If only the final manifest write was interrupted and the matching DB identity has
already committed, stop the app and explicitly resume:

```bash
python -B -m scripts.configure_storage resume --data-dir /private/durable/cyberdash --confirm-resume
```

Resume requires the existing DB and matching identity. It will not create a missing
file or trust an unidentified/partial database. Failures before identity commit
require operator review of the pre-adoption backup and incomplete private state;
do not delete installation markers or retry `init` over existing data blindly.

For lost storage, stop writers, preserve the damaged/mismatched files and restore
a verified matching backup. Do not delete the manifest to make the warning disappear.
Deleting an administrator is not a password reset; restore/recover the account
rather than reopening public setup. A deliberately different restored DB UUID
requires a separate explicit adoption/profile in a stopped maintenance window.

## Back up the installation, not only SQLite

```bash
python -B -m scripts.backup_installation --data-dir /private/durable/cyberdash --output-dir /private/independent-backups
```

Each run creates a unique 0700 directory with a consistent SQLite snapshot,
installation configuration and `backup.json` completion record. It verifies SQLite
integrity, DB identity, required table inventory and administrator setup state,
and records the snapshot's audit head as a checkpoint.
This is **not** proof of full audit-chain verification or of a successful restore.
A failed/incomplete run lacks `backup.json` and never overwrites/deletes a good copy.

For a locally generated `APP_DATA_DIR/signing.key`, add `--include-managed-key` to
include it. Other environment/mounted keys must be backed up by their deployment
secret owner; copying their file paths alone is not backing up their contents.
Exported provider keys/environment overrides also need a separate protected backup.

Use an independent output directory, not inside the live data directory. A second
directory on the same disk does not protect against disk/host loss: encrypt and copy
the bundle to independent off-host storage. The tool does **not** upload it or
automatically prune backups. Retention/off-host transport remain operator choices;
monitor free space and failed runs. Do not lose the only good copy to retention.

### Restore drill

1. Use an isolated host/path, stop writers, and retain the original backup unchanged.
2. Copy `dashboard.db` into the new private data path; preserve the backup's
   settings and original signing key or provide the protected environment key.
3. Inspect the copied DB, then `adopt` it into a **new** private installation directory
   with that key. This records its original DB UUID and backs up the copy before any
   schema work. Do not run adoption against the sole backup file itself.
4. Start on loopback with network feature flags disabled during the drill. Check
   readiness, existing account login, expected counts, snapshot/rule hashes and
   `/api/audit-logs/verify` against the saved checkpoint. Do not trigger feeds,
   asset scans, validation/publication or enrichment to prove recovery.
5. Measure recovery time. Daily successful independent backups target at most
   24 hours of lost changes; no zero-loss/RTO guarantee is implied.

## Docker persistence

The [SQLite Compose example](../deploy/compose.sqlite.yaml) mounts a named volume
and binds the app to loopback. For a **new** installation only:

```bash
docker compose -f deploy/compose.sqlite.yaml build
docker compose -f deploy/compose.sqlite.yaml run --rm --entrypoint python app -B -m scripts.configure_storage init --data-dir /app/data --confirm-new
docker compose -f deploy/compose.sqlite.yaml up -d
```

For replacement/reboot, reuse the same named volume. Never repeat `init` as an
automatic web entrypoint. `docker compose down` retains named volumes; `down -v`,
volume deletion and host storage loss do not. The container UID/GID is 10001.
Use mounted secret files or protected deployment settings for environment-managed
secrets. The sample intentionally does not pass an empty JWT variable that would
override the persisted generated key. Docker volume data is not backed up by images.

F1 cloud guards remain unchanged: no paid storage, paid DB, Always On or SKU change.
The existing storage-disabled cloud configuration cannot satisfy durable SQLite
provisioning and is intentionally not silently repaired. External support will need
its own validated operator-supplied configuration in later stages.

## Boot startup and scheduled backups on a host

Templates are provided in [deploy/systemd](../deploy/systemd/). They are examples,
**not installed/enabled by this change**. Review paths/user/permissions first:

- App checkout/virtualenv at `/opt/cyberdash`, service user/group `cyberdash`.
- Private `/var/lib/cyberdash` and `/var/backups/cyberdash` owned by that user.
- Explicit init/adopt as that user; never initialize the root user's data directory
  and expect an unprivileged service to see it.
- Optional `/etc/cyberdash/runtime.env` for settings/secret references, restricted
  appropriately. Do not regenerate the signing key in a systemd `ExecStart`.
- Install the service/timer files after review. Enable the app for boot startup;
  enable the persistent daily backup timer and check its journal and output copies.
- The backup template assumes a locally generated managed key. If keys are externally
  managed, remove `--include-managed-key` and arrange independent secret recovery.
- `Persistent=true` schedules a missed timer after boot; it is not an uptime or
  off-host-backup guarantee. Neither a timer nor the backup job relies on F1 app activity.

## Validation and remaining work

Tests run on isolated synthetic data only. See `scratch/test_storage_resilience.py`,
the full `scratch.run_tests` runner, Docker smoke modes and the
[Stage A validation handover](storage-resilience-validation.md).

The next stages remain the portable SQL layer, real PostgreSQL/MariaDB adapters
and locking/migrations, then the environment-aware storage-selection wizard. Do
not provide `DATABASE_URL`/external credentials to this release: they are rejected
explicitly, not treated as permission to fall back to SQLite. No existing database,
new live account, cloud deployment or host systemd configuration was changed here.
