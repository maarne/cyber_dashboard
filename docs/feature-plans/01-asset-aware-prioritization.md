# Feature 1 — Asset-aware vulnerability prioritization

**Status:** implemented following user approval; default-off flag retained for operator enablement.  
**Goal:** answer “Which vulnerabilities matter to the systems we actually use, and why?”  
**Prerequisites:** current CVE/KEV/EPSS services and the shared conventions in [the roadmap](README.md).

## 1. Current state and gap

- `app/services/cve_service.py` stores CVE summaries, severity, CVSS, and EPSS; `cisa_service.py` stores KEV records.
- `app/services/db_service.py` provides global dashboard queries. There is no inventory, software-installation model, CPE applicability/version-range data, or asset-to-CVE relationship.
- `app/services/cve_intel_service.py` distinguishes unknown scores from verified cached facts. New prioritization must preserve that distinction.
- The home page is public. Inventory details and organization-specific risk counts must **not** be added to its unauthenticated context.

## 2. First-release scope

### Include

- An authenticated asset inventory: name, external identifier, environment, owner/team, business criticality, Internet exposure, and tags.
- Installed-software records with vendor/product/version as user-provided facts, not verified scanner results.
- Manual CRUD and a downloadable CSV template, import preview, row-level validation, and explicit confirmation.
- Explicit asset-to-CVE associations, with source, evidence note, confidence, and assessment status.
- An explainable priority queue and asset detail page, with filters and safe CSV/JSON export.
- Assessment states: `open`, `in_progress`, `remediated`, `not_affected`, `accepted_risk`. Record who changed the assessment and why.

### Exclude initially

- Network scanning, endpoint agents, cloud-account discovery, paid CMDB integrations, or automatic patch installation.
- Claims that a software-name substring or a guessed version comparison proves exposure.
- Full NVD CPE applicability evaluation, SBOM ingestion, tickets, or automatic case creation. These can be separate follow-ups after the inventory is trusted.

## 3. Main workflow

1. An admin/analyst adds a system or previews a CSV inventory import.
2. The analyst records installed software and associates a known CVE, documenting the source of the association.
3. The system combines current local CVSS/EPSS/KEV evidence with asset context.
4. The priority queue shows the breakdown, evidence freshness, and any missing inputs.
5. The analyst records remediation or risk acceptance; the change enters the audit chain.
6. The team exports its inventory/assessments before an F1 container replacement when it needs to retain this work.

## 4. Proposed data model

| Table/change | Essential fields and constraints |
| --- | --- |
| `assets` | `id`, unique normalized `external_id`, `name`, `environment`, `owner_team`, criticality `1..4`, exposure `internet/internal/unknown`, `is_archived`, `row_version`, actor IDs, UTC timestamps |
| `asset_tags` | `asset_id`, normalized tag; unique pair, bounded tag count/length |
| `asset_software` | `id`, `asset_id`, vendor/product/version, optional CPE supplied by the user, source, observed timestamp; exact normalized tuple uniqueness per asset |
| `asset_cve_assessments` | `id`, `asset_id`, normalized `cve_id`, optional software ID, association source/confidence/evidence, assessment state, reason, accepted-risk expiry, `row_version`, actor/time fields; unique asset/CVE pair |
| `asset_assessment_events` | Append-only state/association changes with actor and before/after context; no credential or raw import contents |
| `cves` addition | Nullable `epss_fetched_at`, updated only when that CVE receives a score; existing rows remain “freshness unknown” until refreshed |

- An association may reference a CVE not yet in `cves`: retain it, label intelligence unavailable, and do not manufacture scores. Do not require a foreign key to a feed row that may not exist.
- Soft-archive assets so assessments and later case references remain valid. Hard purge is outside this release.
- Index external ID, environment, archive state, assessment state, asset/CVE lookup, and tag joins.
- Add versioned migration and repeated-startup tests; create no real inventory rows during migration.

## 5. Matching and priority semantics

### Association safety

An explicit association means “an analyst/source asserts this asset may be affected,” not “CyberDash scanned this machine.” Store `confirmed` versus `suspected` association confidence separately from the assessment state. Optional keyword suggestions must be labeled **candidates** and require confirmation before entering the affected-assets queue.

### Proposed v1 formula

Use a transparent internal ranking score, **not a probability of compromise**:

| Component | Points |
| --- | --- |
| CVSS | `40 × CVSS / 10` |
| EPSS | `20 × EPSS` |
| Confirmed KEV membership | `20` when true, `0` when verified false |
| Business criticality | `0 / 5 / 10 / 15` for criticality 1–4 |
| Internet exposure | `5` for Internet-facing, `0` for explicitly internal |

- Bound the complete score to `0..100`; include `formula_version="v1"` and every input/component in the response.
- If an input is unknown, return a **null complete score**, a known-component subtotal, and a missing-input list. Do not turn missing CVSS/EPSS, an unfetched KEV catalog, or unknown exposure into “low risk.” Zero is a valid known CVSS/EPSS value.
- Confirmed KEV findings receive an independent “known exploited—review urgently” flag even if other inputs are missing.
- Suggested freshness warnings: EPSS older than 48 hours and KEV catalog older than 48 hours. These are configurable development defaults, not feed availability guarantees. Display NVD synchronization state separately from individual modification dates.
- Exclude remediated/not-affected items from the default actionable queue. Accepted risks remain visible with their reason/expiry; expired acceptance returns to actionable review without erasing history.
- Compute on demand for the bounded first release; cache later only with explicit invalidation on feed, asset-context, and formula changes.

## 6. Proposed API and permissions

| Route | Access / behavior |
| --- | --- |
| `GET /api/assets`, `GET /api/assets/{id}` | Authenticated; paginated/filterable inventory |
| `POST /api/assets`, `PATCH /api/assets/{id}` | Analyst/admin; optimistic concurrency on updates |
| `POST /api/assets/{id}/archive` | Admin; preserves evidence/history |
| `GET/POST /api/assets/{id}/software` | Authenticated read; analyst/admin write |
| `PATCH/DELETE /api/assets/{id}/software/{software_id}` | Analyst/admin; reject or explicitly detach linked associations rather than silently deleting them |
| `GET/POST /api/assets/{id}/cves` | Authenticated read; analyst/admin association creation |
| `PATCH /api/asset-assessments/{id}` | Analyst/admin; state/reason/version validation |
| `POST /api/assets/import/preview`, `/api/assets/import/commit` | Admin; short-lived preview token bound to caller and exact validated content |
| `GET /api/priorities`, `/api/assets/export` | Authenticated, bounded queries; admin-only bulk inventory export by default |

No route connects to an asset address. New HTML `/assets`, `/assets/{id}`, and `/priorities` pages use the same authorization as their APIs. Machine-role access is explicit; audit attribution uses the real token ID, never a supplied username.

## 7. UI and implementation map

- Add `asset_service.py`, `prioritization_service.py`, asset/prioritization schemas, and focused routes in/registered by `app/main.py`.
- Add `assets.html`, `asset_detail.html`, and a small `assets.js`; reuse existing themes and form/modal styles.
- The queue shows “reason for priority,” missing/freshness badges, assessment state, and linked CVE/asset details. Sorting must not hide urgent KEV findings among unknown scores.
- Reuse existing CVE details without triggering an upstream fetch for each row. Extend EPSS ingestion to persist score timestamps.

## 8. Staged implementation

1. **Contracts/migration:** freeze fields and limits, migration ledger, canonical actor IDs, constraints, and fixtures. Exit: upgrades preserve current users/feeds/rules/audit entries.
2. **Inventory:** services/API, CSRF-protected forms, software CRUD, archive handling, audit integration. Exit: private inventory never appears on public pages.
3. **Import/export:** CSV parsing and preview/commit with normalization, duplicate handling, version checks, safe CSV cells, and file/row limits. Default duplicate behavior is explicit merge by external ID; never replace the entire inventory.
4. **Associations/scoring:** manual evidence and assessment workflow, known/unknown scoring, freshness, and queue filters. Exit: fixed fixtures produce reproducible score explanations.
5. **UI/review:** complete the add → associate → prioritize → remediate journey, accessibility/theme/browser tests, performance measurement, and operator documentation.

## 9. Tests and acceptance criteria

- Roles, anonymous requests, imports/exports, archived assets, invalid state transitions, stale updates, and SQL/XSS/CSV payloads are covered.
- Import rejects oversized files, invalid CVE IDs, duplicate conflicting rows, and changed inventory between preview and commit. Failed validation makes **no partial changes**.
- Tests distinguish unknown from known zero scores; verify KEV overrides, accepted-risk expiry, and refreshed EPSS changing the ranking.
- No guessed software match automatically becomes confirmed affected status.
- Two-worker edits/import commits serialize correctly and audit events match committed changes.
- Proposed starting limits: 500 active assets, 5,000 software records, 1 MiB/1,000-row CSV imports, and 100-row API pages. Measure queue/import resource use before adjusting them.
- Existing suites and F1 guards pass; a fresh database still completes onboarding normally.

## 10. Rollout, recovery, and later choices

Ship behind `FEATURE_ASSET_PRIORITIZATION`, off until migration and demo acceptance pass. Disabling it hides new navigation/routes without deleting tables. Version exports so later local re-import can be validated; do not promise automatic recovery from F1 data loss.

**Recommended defaults to approve:** manual/CSV inventory, explicit CVE associations, proposed scoring weights, analyst CRUD/admin archive/import, and admin bulk exports. Later automatic matching requires a separate CPE/version-data design and accuracy test corpus—not merely enabling fuzzy search.

## 11. Implementation handover

The approved defaults above are implemented. See [operator documentation](../asset-prioritization.md)
for enablement, permissions, imports, limits, error behavior, score semantics,
backup/recovery, and verification commands. Features 2–5 have not been started.
See the [validation record](../asset-prioritization-validation.md) for test and
browser coverage, Docker checks, measured limits, and remaining operating caveats.

Implementation modules: `app/migrations.py`, `app/models/asset_schemas.py`,
`app/asset_routes.py`, `app/asset_security.py`, `app/services/asset_service.py`,
`app/services/prioritization_service.py`, inventory/priority templates, and vanilla
`assets.js`/`assets.css`. Existing EPSS ingestion now timestamps refreshed scores;
feed state retains last successful synchronization after a later failure.

Queue computation remains local/on-demand and bounded by 10,000 associations.
Evidence/reasons are hydrated only for the requested page. No cloud resources,
paid infrastructure, scanning, fuzzy matching, or automatic patching were added.

## 12. Optional availability extension (implemented, default off)

See [Feature 1A — Configurable asset availability checks](01a-asset-availability-monitoring.md)
for the requested follow-up plan: explicit IP/hostname targets, per-asset curl/
ping/optional single-port nmap checks, private status/history, safe target scope,
and best-effort scheduling. This separately gated extension was approved and
implemented; actual probes still require explicit destination authorization.
The base feature retains its no-asset-network-contact boundary. Down/Unknown assets remain in vulnerability
prioritization, and the existing scoring formula is unchanged.

## 13. Optional discovery extension (implemented, default off)

[Feature 1B — Multi-network discovery and selective import](01b-network-discovery-and-selective-import.md)
extends the follow-up scope to authorized network discovery with optional hostname
resolution, independently scheduled multi-network profiles, arbitrary positive
requested intervals, and quick selective candidate import. Discovery does not
automatically add assets, enable monitoring, change vulnerability assessments, or
start Features 2–5. Implementation was approved; real scans still require explicit
destination authorization. See [operating guidance](../asset-network-operations.md).
