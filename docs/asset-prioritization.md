# Asset-aware vulnerability prioritization (Feature 1)

This is private, manually maintained inventory and **explicit analyst/source CVE
associations**. It does not scan assets, infer vulnerable versions from names,
contact asset addresses, or install patches. No external request is made to
calculate or display priorities; refresh the existing feeds separately.

## Enable locally

1. Back up the existing SQLite database with `scripts/backup_database.py` before
   the first startup of this release. See the main README's backup instructions.
2. Keep your existing `JWT_SECRET_KEY` and `DATABASE_PATH` settings. Set:

   ```bash
   export FEATURE_ASSET_PRIORITIZATION=true
   # Set this to your browser-facing origin behind a reverse proxy:
   export PUBLIC_BASE_URL=http://127.0.0.1:8000
   # Optional; EPSS/KEV warning threshold, in hours (default 48):
   export ASSET_INTEL_STALE_HOURS=48
   python -m app.main
   ```

3. Sign in and open **Inventory** (`/assets`) or **Priorities** (`/priorities`).
   First-time installations must still complete normal administrator setup.

Settings are process environment variables; merely editing `.env.example` does
not apply them. Restart every worker after changing the flag or public origin.
With the flag omitted/false, feature URLs return 404, navigation and OpenAPI
entries are absent, and existing application workflows remain available.

The additive startup migration runs under the existing write lock even if the
feature is disabled. It creates empty domain tables and a migration ledger,
adds nullable per-CVE EPSS timestamps, and preserves the last successful feed
refresh independently of a later failure. Existing intelligence and accounts
are retained. Old EPSS rows retain **unknown freshness**, not invented timestamps.

## Permissions and privacy

| Action | Allowed |
| --- | --- |
| Inventory, software, CVE assessments/history, priorities | Authenticated viewers, analysts, admins |
| Create/edit assets, software, associations and assessments | Analysts/admins |
| Archive/restore, CSV template/import, bulk JSON/CSV export | Admins |

Machine tokens have their assigned role's permissions and are attributed by real
token ID. Human sessions use canonical account IDs. No organization-specific
data or counts are added to public pages. Feature responses are `no-store`.

Cookie-session mutations require `X-CSRF-Token` plus a matching `Origin` or
`Referer`. The UI handles this automatically. Cookie-based custom clients can
retrieve their token from authenticated `GET /api/assets/session`. Behind a
reverse proxy, configure `PUBLIC_BASE_URL` to the exact external scheme/host/port;
forwarded headers are not used to choose a trusted origin. Without this setting,
the request's base origin is used. Explicit Bearer/API-key credentials are
separate from cookie authentication and do not require CSRF headers. Invalid
explicit credentials never fall back to a session cookie.

## Suggested demonstration

1. Add a development asset with a unique external ID, criticality, exposure,
   owner/team, and tags. Identifiers, environments, and tags are normalized.
2. Add a software observation (vendor/product/version and optional user CPE).
3. Associate a CVE and explain why it may apply. Optionally link that asset's
   software record ID. Choose suspected/confirmed confidence independently of
   assessment state. Neither means CyberDash performed a scan.
4. Review the queue's **Why this priority?** details: inputs, weighted points,
   missing data, freshness, association evidence, and source synchronization.
5. Use **Assess / edit** to record progress, a remediation/not-affected reason,
   or a risk acceptance with a future UTC expiry. Inspect the preserved before/
   after history and audit references.
6. Export important work before replacing an ephemeral F1 container.

Archived assets retain evidence/history and are excluded from the default queue.
Restore them explicitly before editing. Linked software cannot be deleted until
its assessments are edited to clear the software link. Hard asset/assessment
deletion is intentionally unavailable.

## Ranking contract (formula v1)

`4 × CVSS + 20 × EPSS + (KEV ? 20 : 0) + 5 × (criticality − 1) + exposure points`

- Criticality is 1–4. Exposure is 5 for Internet-facing, 0 for explicitly internal,
  and unknown otherwise. A complete score ranges from 0–100.
- Missing/invalid CVSS or EPSS, unfetched KEV membership, or unknown exposure
  produces `score: null`, `known_subtotal`, and `missing_inputs`. **Known zero
  values are valid.** A cached KEV entry confirms membership even without a feed
  status row; negative membership requires a successfully fetched catalog.
- KEV-positive rows sort first even when other inputs are missing. Remaining
  rows sort descending by complete score or known subtotal, then stable ID.
  Incomplete subtotals are not directly comparable to complete scores.
- EPSS and KEV show warnings when older than the configured threshold or when
  freshness is unknown. A failed KEV refresh preserves the last successful
  catalog's interpretation and adds a failure warning. NVD sync state is shown
  separately from an individual CVE's modification timestamp.
- Default actionable states are `open` and `in_progress`. Remediated/not-affected
  items are excluded. Unexpired accepted risks are visible under **All states**
  or **Accepted risk**. Expired acceptance is effectively open for review; its
  stored disposition, reason, expiry, and event history are not rewritten.
- Scores are **internal rankings, not probabilities of compromise**.

## CSV preview and commit

Download the version-1 template from Inventory. Headers must be in the original
order. `tags` and `cve_ids` are semicolon-separated; CSV quoting is supported.
Repeated external IDs are allowed for multiple software rows only when their
asset fields agree. Case-insensitive software tuples deduplicate; conflicting
asset fields, CPEs, or repeated CVE evidence reject the entire preview.

Preview validates every row before any inventory mutation. It displays normalized
content, counts, and merge policy. The commit token is hashed at rest, caller-
bound, valid for ten minutes, and usable once. Any inventory mutation invalidates
an older preview through the shared revision counter. A newer preview replaces
that caller's previous pending preview; at most 20 pending previews are stored.

Commit merges asset fields by normalized external ID and adds missing software
and CVEs. Existing software observations and assessment evidence/states are
**preserved**, not overwritten. CSV-created associations are suspected, open,
and asset-level; link specific software explicitly if appropriate. Archived
identifiers must be restored before import. No whole-inventory replacement,
implicit archive/restore, or partial commit occurs. Audit failure rolls back the
domain change and token consumption together.

Limits:

- 500 active assets, 5,000 retained software rows, 10,000 retained associations.
- 1 MiB UTF-8 CSV and 1,000 data rows; 100 rows per API page.
- Asset tags: 10, each at most 32 characters. Evidence/reasons: 4,000 characters.
- Ordinary mutation JSON bodies: 64 KiB, bounded before JSON parsing. Import
  preview transport permits JSON escaping overhead (6 MiB + 64 KiB), but the
  decoded CSV must still be at most 1 MiB. Import parsing is all-or-nothing.

Exports have schema version 1. JSON preserves inventory, software, and current
assessment evidence/states. CSV is a formula-escaped summary with an extra
`archived` column, not a round-trip import file; use the template for imports.
Neither export is a full restore of identities, audit chain, or event history.
Use a consistent database backup for full recovery. Treat exports as sensitive.

## API notes and errors

OpenAPI and the existing API explorer list the feature's routes and required
roles when enabled. The UI uses `/api/assets`, nested `/software`, `/cves`,
`/events`, `/api/asset-assessments/{id}`, and `/api/priorities`.

Updates, software deletion, and archive/restore require `expected_version` from
the record's `row_version`. A stale write returns 409; reload and review rather
than silently overwriting someone else's edit. Other standard errors: 401 for
missing/invalid authentication, 403 for role/CSRF/origin rejection, 404 for absent
records, 413 for transport/CSV row/byte limits, and 422 for input/CSV row errors.
Conflicting uniqueness, linked software deletion, archive edits, expired/stale
previews, and quotas return 409. No failed validation partially changes inventory.

## Recovery and free-tier limits

Set the feature flag false and restart to disable routes without deleting data.
Do not drop the tables or run destructive down-migrations. A full rollback to a
pre-migration database requires a verified backup and intentionally loses later
writes; do not assume an older binary understands new feature state.

This feature does not change hosting, F1 guards, Always On, persistent storage,
or scheduling. Azure F1 can sleep or lose its SQLite file on replacement. Local
Docker volumes/SQLite backups can retain development data; no durability or
uptime guarantee is introduced. No cloud resources are provisioned or deployed.

Validation commands (isolated databases):

```bash
python -m scratch.run_tests
python -m scratch.benchmark_asset_prioritization
docker build -t cyberdash:asset-prioritization .
python -m scratch.container_smoke cyberdash:asset-prioritization --assets
```

The smoke test uses two workers and removes only its uniquely named local test
container/volume. Its persistence check is a local Docker test, not a change to
Azure's intentionally ephemeral configuration.
