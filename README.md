# CyberDash — Cybersecurity Dashboard

FastAPI, SQLite, and vanilla HTML/CSS/JavaScript for vulnerability feeds,
threat intelligence, IOC investigations, Sigma/YARA rule management, and alerts.

![Project screenshot](images/screenshot_v1.jpg)

## Local development

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# NEW installations only: durable data, settings and a generated private signing key.
# Existing installations: inspect/adopt instead; see the storage guide below.
export APP_DATA_DIR="$HOME/.local/share/cyberdash"
python -m scripts.configure_storage init --data-dir "$APP_DATA_DIR" --confirm-new
python -m app.main
```

Open <http://127.0.0.1:8000> and complete the administrator setup wizard.
There is **no default administrator password**. Provision the initial account
before exposing a new instance publicly. The primary account is protected by
database identity, not its username.

**Upgrade/recovery:** [storage initialization, adoption and backups](docs/storage-resilience.md).
Startup no longer silently creates a missing database or adopts a workspace file.
The current server's [persistent 8765 instance](docs/local-instance-8765.md) has
separate boot-service, backup and recovery instructions.

Use **Refresh Feeds** after logging in as an analyst or administrator. Live
feeds need outbound Internet access. NVD requests are paginated and paced to
respect its public limits; an initial refresh can take longer than one request.
The initial NVD import covers the last seven days of modifications; subsequent
runs use a persisted watermark. CISA KEV imports the complete catalog.

### Configuration

| Variable | Purpose |
| --- | --- |
| `APP_DATA_DIR` | Private durable installation directory; defaults to `$XDG_DATA_HOME/cyberdash` or `~/.local/share/cyberdash`. Docker uses `/app/data`. |
| `JWT_SECRET_KEY` / `JWT_SECRET_KEY_FILE` | Alternative secret sources; never set both. Otherwise use the private signing-key file recorded during initialization. No automatic replacement on restart. |
| `DATABASE_PATH` | Optional explicit SQLite path; must match the installed profile. Otherwise use the profile's recorded path. |
| `ALLOW_EPHEMERAL_STORAGE` | Explicit disposable/test mode only; false by default. Temporary/unmounted storage is refused for durable provisioning. |
| `EXPECTED_DATABASE_ID` | Optional additional pin to the configured database's identity UUID. |
| `ENV` | Set to `production` for HTTPS-only session cookies behind a trusted TLS proxy. |
| `NVD_API_KEY` | Optional NVD key for higher request throughput. |
| `URLHAUS_API_KEY` | Optional Abuse.ch feed credential. |
| `URLHAUS_RECENT_URL` | Optional trusted operator override of the URLhaus source. |

For a persisted local environment, copy `.env.example`, configure the installation
directory and either a secret source or the installed key (remove the empty
`JWT_SECRET_KEY=` entry when using the latter), then run
`.venv/bin/uvicorn app.main:app --env-file .env --reload`.
Never commit `.env` or copy a development secret into production.

## Access and API

- Guests can view the public intelligence dashboard, actor directory, and rule catalog.
- Authenticated viewers can read APIs and shared investigation history.
- Analysts/admins can investigate IOCs, author rules, and refresh feeds.
- Admins manage accounts, tokens, feeds, schedules, and alert destinations.
- Deletion, role changes, and password changes invalidate existing sessions;
  logout revokes the current session across workers.
- Machine tokens support `X-API-Key: cd_live_...` or `Authorization: Bearer cd_live_...`.
  Only hashes are stored. Per-token fixed-minute limits are enforced in SQLite;
  excess requests return **429** with `Retry-After`.

Interactive documentation: `/docs`, `/redoc`, `/openapi.json`.
The Settings API explorer derives routes from OpenAPI rather than an independent
hard-coded catalog. Investigation uses **GET `/api/investigate?ioc=...`**;
rules use **`/api/detection-rules`**.

Public operational probes: **`/api/health`** (liveness) and **`/api/ready`**
(database readiness, including before administrator setup).

Unknown intelligence is reported as unknown—not fabricated CVSS scores or
VirusTotal detections. Curated CVE descriptions are explanatory only; live
ratings take precedence. IOC matching is exact and type-specific. External
pivot links are not evidence that those services were queried.

## Tests

```bash
.venv/bin/python -m scratch.run_tests
# Run just the review regressions:
.venv/bin/python -m scratch.test_review_regressions
# Optional: build the image, then check two-worker behavior and persistence:
docker build -t cyberdash:review-fixes .
.venv/bin/python -m scratch.container_smoke cyberdash:review-fixes
```

The runner executes each suite in its own process. Test fixtures replace any
inherited database path and signing secret before importing the application.
Older requests-style checks use an **in-process TestClient**, not a live server.
Unexpected outbound HTTP is blocked. Do not collect the independently bootstrapped
suites together in a single interpreter; use the runner above.

## Hosting and backups

The Docker image runs as a non-root user. Mount a durable volume at `/app/data`,
owned/writable by UID/GID **10001**. Provision a new volume explicitly, then reuse it:

```bash
docker build -t cyberdash .
docker run --rm -v cyberdash-data:/app/data --entrypoint python cyberdash -B -m scripts.configure_storage init --data-dir /app/data --confirm-new
docker run --restart unless-stopped -p 127.0.0.1:8000:8000 -v cyberdash-data:/app/data cyberdash
```

Azure Bicep/pipeline configuration is **development-only F1 (Free)**. Both Bicep
templates reject paid SKUs; there is no automatic paid-tier fallback. Always On
and persistent App Service storage are disabled. The durability guard now refuses
normal SQLite provisioning in an unmounted container layer; the unchanged F1
deployment needs an explicit future storage configuration rather than silently
creating ephemeral accounts/data. Disposable opt-in cannot guarantee persistence.
The app can sleep or stop under F1
quotas; scheduled refreshes are not guaranteed while it is idle.

Configure an Azure DevOps **secret variable** named `jwtSecretKey` before
deployment. `ENV=production` remains set solely to enforce secure HTTPS cookies;
it does not select a paid hosting tier. Existing `prod` resource/stage identifiers
are retained for compatibility, not as a production-readiness claim.
No deployment runs from feature branches.
Tests, quality gates, high/critical dependency/container findings, Semgrep
findings, DAST failures, and failed readiness probes block deployment. ZAP warnings
remain advisory. Environment approval policies are configured separately in Azure.

F1 requests remain subject to Azure subscription, regional, and workload support.
If Azure rejects F1 for the container workload, deployment must fail rather than
upgrade to a paid plan. This configuration does not provision paid storage,
databases, registries, or monitoring. CI minutes and third-party services still
depend on your existing free allowances; a code change does not remove charges
from any resources already running in Azure.

SQLite is intended for a single deployment instance. Validate filesystem locking
on the selected persistent storage; network filesystems can have SQLite locking
limitations. Use a server database before horizontal scaling. Persistence is
**not** a backup. Optional local systemd backup/service templates are supplied but
are not installed/enabled automatically; see [storage operations](docs/storage-resilience.md).

Create a consistent backup (output must not already exist):

```bash
python -m scripts.backup_database --database /path/cyber_dashboard.db --output /backup/cyberdash-2026-11-01.db
```

Keep encrypted/off-host backups with retention appropriate to your organization.
To restore: stop **all** application workers, retain the current database and any
journal/WAL files as a separate recovery copy, restore the verified backup at
`DATABASE_PATH`, set ownership/permissions, then restart and check `/api/ready`.
Test restores in a separate environment before relying on them.

### Audit integrity and upgrades

New audit entries use canonical JSON SHA-256 chaining, including IP addresses,
and append under a database write lock. Existing v1 entries are preserved and
reported as legacy; their IP fields were never protected. This is **not** an
immutable ledger or a Merkle tree. Verification returns a checkpoint
(`id`, `integrity_hash`); save it outside the application database and supply
`checkpoint_id` and `checkpoint_hash` to `/api/audit-logs/verify` to detect tail
deletion or rewriting relative to that checkpoint.

**Before upgrading:** take a backup, configure the signing secret, and plan for
existing browser sessions to be invalidated. Migrations run at startup; this
change does not rewrite existing audit history or automatically clean up legacy
intelligence records. Rotate secrets and review data imported by older releases.

## Asset-aware prioritization

Feature 1 adds private inventory, software observations, explicit CVE assessments,
CSV preview/commit, exports, and an explainable priority queue. It is **disabled
by default**. Set `FEATURE_ASSET_PRIORITIZATION=true` and restart to enable it.
See [operation, permissions, scoring, and recovery](docs/asset-prioritization.md).
The base inventory does not scan systems or provision infrastructure.

Optional [availability checks and multi-network discovery](docs/asset-network-operations.md)
extend this workflow with per-asset probes, custom schedules, hostname discovery,
and selective candidate import. They are independently **disabled by default**
and require explicit per-check/profile enablement. The destination scope defaults
to RFC1918 IPv4 networks; an operator CIDR override replaces that default, and an
explicitly empty override denies all targets.
No real networks were scanned during implementation.

## Feature roadmap

**Reliability initiative:** [Stage A storage hardening](docs/storage-resilience.md)
is implemented. The [approved staged plan](docs/feature-plans/00-database-resilience-and-external-databases.md)
also covers portable SQL access, PostgreSQL/MariaDB and a database-selection wizard;
those later stages are **not implemented yet**. External connection settings are
rejected rather than silently falling back to SQLite.

[Investigation case management](docs/investigation-cases.md) adds team-visible
analyst/admin cases, local-only IOC captures, preserved evidence, append-only
notes, close/reopen history and JSON/Markdown reports. Enable it with
`FEATURE_CASE_MANAGEMENT=true`; it is independent of asset monitoring and default off.

[Detection-rule lifecycle](docs/detection-rule-lifecycle.md) adds immutable revisions,
local Sigma/YARA validation, independent human-admin review, controlled publication,
private drafts, diffs and rollback drafts. Enable `FEATURE_RULE_LIFECYCLE=true`
after a backup. Existing rules remain public as **legacy/unreviewed**; disabling
the flag after activation leaves the managed catalog read-only, not mutable.
Syntax validation is not proof of detection efficacy; nothing is deployed.

Detailed plans for the five features are in
[the feature-plan roadmap](docs/feature-plans/README.md). Features 4–5 remain
proposals. Features 1–3 are implemented behind their
default-off flags. Features are implemented one at a time after approval,
without changing the F1-only, zero-paid-infrastructure development constraint.
