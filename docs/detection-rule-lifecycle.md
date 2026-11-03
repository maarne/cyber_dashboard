# Detection-rule lifecycle: operation and privacy

Feature 3 is **default off**, independent of asset and case flags. It adds no paid
service, SIEM connection, scheduler, cloud resource or frontend build tooling.
See [validation and rollout status](detection-rule-lifecycle-validation.md).

## Enable safely

1. Stop writers and take a consistent SQLite backup (use `scripts/backup_database.py`;
   do not copy an active database file blindly). Save the current private settings,
   signing key and an audit checkpoint separately, outside ephemeral hosting.
2. Install `requirements.txt` using Python 3.11+ on Linux. The Docker build installs
   wheels only; it does not add compilers. Build and smoke-test before rollout.
3. Set `FEATURE_RULE_LIFECYCLE=true`, preserve the existing `DATABASE_PATH`,
   `JWT_SECRET_KEY`, network scope and other flags, and restart the current code.
   Set `PUBLIC_BASE_URL` to the browser origin when behind a proxy.
4. Migration 4 adds lifecycle tables and snapshots every existing rule exactly,
   including nulls and whitespace, with **unknown legacy authorship**. IDs remain
   stable. No legacy rule is repaired, validated, approved or published anew.
5. Confirm `/api/health`, `/api/ready`, the public `/rules` legacy warning, and the
   analyst/admin-only `/rule-workbench`. Verify old content/IDs and other data.
   Do not validate real rules or create demo users/rules as a rollout health check.

Activation persists as `app_settings.rule_lifecycle_activated=true`. Afterwards,
flag-off hides the workbench and mutation routes but keeps published/legacy reads.
Legacy POST/PUT/DELETE cannot bypass the latch. **Do not roll back to older code
that lacks the latch.** Full recovery uses a verified pre-upgrade backup while
writers are stopped; it loses subsequent writes. There is no destructive down-migration.

## Analyst / reviewer workflow

1. Open **Public catalog → Private rule workbench** as an analyst/admin. New rules
   start as private drafts; editing saves another complete immutable revision.
2. Validate the **saved revision**. Unsaved editor text is not validated/submitted.
   A report binds the complete snapshot SHA-256, validator policy/version and actor.
3. Submit a valid current draft. Submission freezes it; editing a frozen candidate
   requires **Withdraw to a new draft**.
4. A **different human admin** reviews and records an approval/rejection reason.
   Machine tokens may author/validate/submit but cannot approve, reject or publish.
   A single-person installation must arrange a second reviewer; no self-review bypass.
5. A human admin explicitly publishes the approved revision. The exact submitted
   validation, hash, policy and current admin status of the reviewer are rechecked.
   Publication atomically changes the public pointer and appends its audit event.
6. A private successor leaves the current public rule unchanged. Diff and history
   inspect preserved source/metadata. **Rollback creates a new draft**, even when
   its content hash matches an old approved revision. Validate/review/publish again.
7. Admin archive hides the identity from public catalog/downloads and blocks edits;
   restore retains the same history/pointers. Prior case-reference labels survive.

Snapshots are immutable through supported application APIs, not an encryption or
database-administrator security boundary. Digest mismatches warn privately and
block use/public downloads. Audit verification and external checkpoints are still needed.

## Public versus private contracts

| Interface | Snapshot / authorization |
| --- | --- |
| `GET /rules` | Public; published pointer or exact legacy/unreviewed snapshot only |
| `GET /api/detection-rules[/{id}]` | Authenticated viewer+; same public projection, never working state |
| `GET /api/detection-rules/{id}/download` | Public, as the catalog source already is; exact public source plus comment notice and revision/hash headers |
| `GET /api/rule-lifecycle/rules` | Analyst/admin; working collection, keyset-paged, optional `archived=true` |
| `GET /api/detection-rules/{id}/working` | Analyst/admin; current private working snapshot and public pointer |
| `/revisions`, `/revisions/{revision_id}`, `/diff?older=…&newer=…` | Analyst/admin; private history and escaped source/metadata diff |
| `GET /api/detection-rules/{id}/revisions/export` | Analyst/admin; version-1 JSON history, validation reports/reviews/events; security-audited consistent read |

Download SHA-256 covers the **original complete canonical snapshot**, not the
extra download comments or source alone. Downloads are not converted SIEM queries
and exports are not deployable bundles. An archived/private identity returns 404
on public detail/download. Public search never searches private source or metadata.
Source/guidance/diffs render as text, not executable HTML/Markdown.

Private drafts/history are shared by the analyst/admin team, not author-only.
Reports/exports include actor IDs/display names, source, review reasons and internal
guidance; treat them as sensitive. They do not include settings, credentials or
provider keys. Feature routes use private/no-store responses. Cookie writes require
session-bound CSRF and a trusted origin; explicit credentials use existing RBAC.

### Mutation compatibility

- `POST /api/rule-lifecycle/rules` creates a draft (201); compatibility
  `POST /api/detection-rules` delegates to the same bounded snapshot validation.
- `POST /api/detection-rules/{id}/revisions` requires the complete snapshot,
  `expected_version` and `expected_parent_revision_id`.
- `POST /api/detection-rules/{id}/revisions/{revision_id}/{validate,submit,withdraw,review,publish}`
  uses `expected_version`; review also requires `decision` and `reason`.
- `POST /api/detection-rules/{id}/rollback` adds `source_revision_id` and `reason`;
  `/archive` adds `archived` and `reason`.
- Old mutable PUT and hard DELETE return **409** after activation. Reload after a
  stale-version 409; no last-writer-wins edit is performed.
- 401/403 mean authentication/authorization/CSRF failures; 422 means invalid bounded
  input; 413 means body/export too large; 503 with `Retry-After` means validator slots busy.

## Validation boundaries

**Syntax/structure validation is not proof of detection efficacy or SIEM compatibility.**
There are no malware samples, file/memory scans, efficacy tests, includes, YARA module
imports, Sigma plugins/backends, remote conversion, user templates or deployment.

- Sigma: pinned pySigma parses/resolves selectors and conditions; safe PyYAML rejects
  multiple documents, aliases/anchors/tags, duplicate keys, >20 nesting and >10,000
  parse events. Required metadata: title, canonical UUID, status, level, logsource,
  detection. Unsupported timeframe/aggregation is rejected. Optional CVE/TTP labels
  are checked structurally; platform labels are not integration-tested.
- YARA: pinned native binding compiles **source only** with file includes disabled.
  Includes/module imports are rejected before compilation. No matching scan is run.
- Each child has a fresh secret-free environment and isolated Python import mode;
  no inherited database/signing/provider configuration. Three-second wall deadline
  includes pipe input/output, two-second CPU limit, 128 MiB address-space limit,
  32 file descriptors, no core/file output and Linux `no_new_privs`.
- Two SQLite-leased slots are shared across web workers; no waiting queue. Lease
  expiry recovers capacity after a parent crash. Validation does not hold a database
  transaction while parsing. Worker crash/output overflow/timeout/missing dependency
  never produces a valid result. This is process/resource isolation, **not an OS
  sandbox against native-library vulnerabilities**; keep libraries patched and
  restrict authoring to trusted team members.
- Reports record `valid`, `invalid` or `error`, errors/warnings, reason, duration and
  version. After a validator policy/dependency change, a frozen approval cannot be
  published; withdraw to a new draft and validate/review under the new policy.

## Storage / F1 limits and recovery

| Budget | Limit |
| --- | ---: |
| Retained identities / revisions per identity | 500 / 50 |
| Retained complete snapshot payloads | 50 MiB total |
| Source per new revision | 200 KiB UTF-8 |
| Validation runs per revision / child stdout | 20 / 32 KiB |
| Domain events per identity | 500 |
| Global report / event-detail / review-reason payloads | 10 MiB each |
| History export / mutation request body | 20 MiB / 1,500,000 bytes |

Count/storage exhaustion rejects the whole transaction. Nothing prunes retained
history; archive/export does **not** reclaim quota. Export/back up and plan an
explicit reviewed storage/retention policy instead of deleting history directly.
Exports that exceed limits fail, never silently truncate. These are payload budgets,
not total SQLite/RAM/image budgets. Audit/index overhead and validation code still
consume space. Legacy migration preserves original content without applying new
source validation; grandfathered legacy catalogs over the new quotas remain readable
without silent truncation, and further quota-consuming writes are rejected.
F1 may sleep or lose its database on replacement. Off-instance
backups of the complete DB, private settings and audit checkpoints remain essential;
per-rule JSON export alone does not restore accounts/cases/settings.

## Pinned dependencies and licenses

Reviewed package metadata: `pysigma==2.0.2` (**LGPL-2.1-only**),
`yara-python==4.5.4` (**Apache-2.0**), `PyYAML==6.0.3` (**MIT**).
Transitive additions are pinned in `requirements.txt`: diskcache-community,
google-re2, jq, pyparsing and types-PyYAML. They are runtime parser dependencies,
not extra services; no arbitrary backend/plugin installation is supported.
Their distribution metadata respectively declares Apache-2.0, BSD (classifier),
BSD-2-Clause, MIT and Apache-2.0; bundled native components may carry extra notices.

Keep upstream license/notice files shipped in the installed distributions. pySigma
remains an unmodified separate Python dependency; distributing the image still
requires honoring its LGPL notices/source/replacement obligations and the other
bundled packages' licenses. Package metadata is not a substitute for a legal
distribution review. Wheel-only CPython 3.11 Linux Docker and local 3.12 were tested;
other platforms/architectures need their own wheel and resource-limit checks.
