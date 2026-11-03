# Storage resilience — Stage A validation handover

**Subsequent deployment:** the user later approved a fresh persistent 8765
installation. It is now running with enabled user services and local backups;
see [the deployment handover](local-instance-8765.md). The implementation-time
findings below describe the earlier pre-deployment state.

Validated locally on 2026-11-02. See [operation/recovery instructions](storage-resilience.md)
and the [approved staged initiative](feature-plans/00-database-resilience-and-external-databases.md).

## Delivery boundary

Stage A adds SQLite durability/recovery safeguards, private persisted installation
settings/key references, operator init/inspect/adopt/status/resume commands, private
backup bundles and deployment examples. No SQLAlchemy/Alembic adapter, PostgreSQL,
MariaDB, external engine installation UI or cloud database is advertised as complete.
Those remain Stages B–F. No dependency or hosting-tier change was needed here.

## Passed checks

- Full isolated regression runner, including the storage resilience suite, existing
  security/auth, assets/network, cases, 20 rule-lifecycle tests and F1-only guards.
- **20 storage tests:** explicit confirmation, existing-file refusal, repeated
  key/identity/settings loading, file permissions, concurrent initializer exclusion,
  original-key requirement and consistent pre-adoption backup, unknown schemas,
  symlinks, unsupported external settings and temporary-storage opt-in.
- Missing DB at startup or during service, empty/wrong DB, corrupted SQLite,
  missing manifest/table/key, deleted admin and incomplete installation all fail
  closed without a new DB/admin/signing key or automatic table/data reseeding.
- Explicit finalization resume requires an existing matching committed DB identity.
  The retired admin-deletion helper makes no database changes.
- Synthetic backup and isolated restore retain database identity, account password
  verification, signing key and audit-chain integrity. Failed subsequent backup
  leaves the previous completed bundle untouched; incomplete bundles have no
  completion marker. SQLite physical file headers may change during a correct
  online backup, so data-equivalence tests compare logical records, not file bytes.
- Docker CPython 3.11 wheel-only build; non-root UID 10001 and two workers. Existing
  smoke modes pass with explicit one-off provisioning: all feature flags off and
  combined rule/case/network flags; state persists across container replacement.
- Dedicated Docker storage drill uses generated **persisted** keys, not a reused
  environment key: accounts/rules and the old signed session survive replacement;
  removing the DB during service and replacing the container leaves it missing,
  readiness 503 and registration closed. Restoring the held original recovers access.
- The same Docker drill rejects unmounted image-layer storage and restores a private
  backup into a separate disposable volume, verifying copied accounts/rules/audit.
- Compose example passes `docker compose ... config --quiet`. Systemd unit/timer
  syntax verified with executable paths substituted for the current checkout;
  `/opt/cyberdash` is intentionally a deployment placeholder, not installed here.
- Changed Python files parse; documentation links and whitespace checks pass.
  Existing FastAPI/httpx TestClient deprecation warnings remain non-failing.

## Reproduce safely

```bash
python -B -m scratch.run_tests
docker build -t cyberdash:storage-resilience .
python -B -m scratch.container_smoke cyberdash:storage-resilience
python -B -m scratch.container_smoke cyberdash:storage-resilience --rules --cases --network
python -B -m scratch.container_storage_smoke cyberdash:storage-resilience
docker compose -f deploy/compose.sqlite.yaml config --quiet
```

Tests use individually owned disposable directories/volumes and synthetic data,
never the workspace candidate or a supplied production connection string. Docker
fixtures remove only their uniquely named containers/volumes. No real scans, feeds,
enrichment or rule validation/publication were triggered in an existing database.

## Local synthetic measurements

A private disposable durable-mode installation with 20,000 synthetic CVEs produced
a 14,778,368-byte SQLite backup. Across 100 guarded connection + user-count reads,
median latency was 2.330 ms and p95 was 8.568 ms. A private backup bundle including
the generated key completed in 336.13 ms. These are local observations, not F1
latency, maximum-load, disk-durability or recovery-time promises. No production
database was used, and the individually owned fixture directory was removed.

## Current server / recovery finding

The workspace-root `cyber_dashboard.db` was inspected read-only and left unchanged:
SQLite quick-check OK, migration ledger `[1]`, one user, 420 CVEs, zero assets and
18 rules. This is not the previously recorded temporary runtime dataset with
17,140 CVEs and asset/network configuration. Its original signing key was not
established or replaced. It was not adopted, moved, migrated or launched.

Nothing was listening on 8765 at final checks. No real host reboot, service
installation/enablement, backup timer enablement, live backup destination, live
secret configuration or live data recovery was performed. Container replacement
tests demonstrate the code path, not a verified resilience guarantee for this
server's disks or a cloud filesystem.

## Operator decisions still required

- Identify whether the older surviving DB should be recovered, another copy exists,
  or a genuinely new installation is desired. Do not treat the candidate as an
  equivalent substitute for the lost data.
- Establish a stable signing-key source (or separately approve deliberate recovery/
  rotation), durable data path/volume, backup destination and off-host transport.
- Review/install host service/timer templates if desired, perform a restore drill
  with the actual selected deployment, and monitor backup success/free space.
- Retention/encrypted off-host upload is not automated by Stage A; partial backups
  and previous successful backups are never silently pruned. Same-host storage is
  not an independent disaster-recovery copy.

Changes remain uncommitted; prior Feature 3 work is preserved. No paid services,
cloud deployment, external database accounts or roadmap Features 4–5 were introduced.
