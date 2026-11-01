# Feature 3 — Validated, versioned detection-rule lifecycle

**Status:** proposed; implement only after approval.  
**Goal:** make rule changes reviewable and reproducible before anyone treats them as deployable detections.  
**Prerequisites:** existing Sigma/YARA catalog and current analyst/admin RBAC; no external SIEM is required.

## 1. Current state and gap

`app/services/rule_service.py` creates, updates, and deletes mutable rows in `detection_rules`. Request schemas bound source length but do not validate Sigma structure or compile YARA. There is no revision history, review state, approval identity, or published-versus-draft boundary.

The `/rules` HTML catalog is public, while its JSON API requires authentication. A lifecycle must enforce visibility on **both** paths. A hidden edit button is not protection for draft code embedded in page HTML.

## 2. First-release scope

### Include

- Immutable numbered revisions of the complete rule snapshot: source, title, type, severity, CVE/TTP links, target platforms, description, and deployment guidance.
- Lifecycle `draft → in_review → approved → published`, plus `rejected`, withdrawal to a new draft, and rule-level archive.
- Structural Sigma validation and resource-bounded YARA compilation with versioned validation reports.
- Independent admin review, rejection feedback, diff/history browsing, and explicit publication.
- Rollback by creating a new revision from an earlier one and re-running validation/review—not rewriting history.
- A clear distinction between “valid syntax,” “approved by our workflow,” and “tested effective in a real SIEM.”

### Exclude initially

- Running malware samples, executing rule-provided scripts, scanning local files, automatic deployment to SIEM/EDR, and arbitrary rule includes/imports.
- Guaranteed detection quality, automated false-positive scoring, all-SIEM conversion, or paid rule-testing services.

## 3. Lifecycle and review rules

1. An analyst/admin creates a draft or a new draft revision of an existing rule.
2. Validation produces a report tied to the exact revision content hash and validator version. An edit creates another revision; it cannot reuse an old “valid” result.
3. Submission freezes the candidate in review. Invalid candidates cannot be submitted; warnings remain visible.
4. A **different human administrator** approves or rejects the candidate with a reason.
5. An administrator publishes that approved, validated revision. Publication atomically changes the public pointer and records the event.
6. Creating a newer draft never replaces the currently published version shown to readers or downloads.
7. Archiving prevents normal deployment/download discovery while preserving revisions and prior case references.

No silent self-approval bypass. In a single-person development setup, create a second local reviewer account; this has no additional hosting/service cost. A future “self-approved development” policy would need separate approval and prominent labeling.

## 4. Proposed data model and migration

| Table/change | Essential fields and constraints |
| --- | --- |
| `detection_rules` additions | Stable identity, nullable `published_revision_id`, current working revision pointer, lifecycle/archive metadata, `row_version` |
| `rule_revisions` | `id`, `rule_id`, monotonically increasing revision number, parent revision ID, immutable complete snapshot, canonical SHA-256, author actor/display name, creation time; unique rule/revision number |
| `rule_validation_runs` | Revision ID/hash, validator name/version, `valid/invalid/error`, structured errors/warnings, duration, executed timestamp; report contents bounded |
| `rule_reviews` | Revision ID, human reviewer ID/name snapshot, `approved/rejected`, rationale, time; author/reviewer separation checked in service logic |
| `rule_lifecycle_events` | Append-only submit/withdraw/approve/reject/publish/archive/rollback events with actor/time and audit reference |

- Backfill each existing row into an exact **`legacy_unreviewed`** revision. Never label seeded or user rules approved/valid simply because they existed before migration.
- Recommended compatibility policy: keep previously public legacy snapshots readable with an unmistakable **unreviewed/unvalidated** banner. New drafts are private. Publishing a validated successor replaces that legacy public snapshot.
- Existing field projections may remain for backward-compatible reads, but immutable revisions and the published pointer become the authoritative lifecycle data. Document exactly which snapshot every endpoint returns.
- Prevent startup seeders and title-deduplication cleanup from overwriting/removing version-managed identities. Migrations must preserve IDs used by case references.
- Retire hard deletion in the normal UI/API in favor of archive; document any compatibility change to the existing DELETE endpoint. Historical revisions must not cascade-delete.

## 5. Validation design

### Sigma

- Use a maintained open-source Sigma parser/schema library; select and pin its version during implementation after license/runtime review.
- Load YAML safely, reject Python/object tags, multiple unexpected documents, alias/expansion abuse, oversized input, and unsupported constructs.
- Validate required metadata, a real UUID where required by the chosen Sigma specification, supported level/status values, `logsource`, selectors, and detection-condition references.
- Validate optional CVE/TTP links structurally and flag unsupported platform mappings as warnings rather than claiming successful conversion.
- Do not execute custom YAML tags, backend plugins, templates, or shell commands from user content.

### YARA

- Prefer a pinned `yara-python` binding with verified Python 3.11 wheels; if a build is required, use a Docker build stage and keep compilers out of the runtime image.
- Compile **source only** in an isolated subprocess. Disable file includes and unapproved modules; do not supply file/network callbacks or scan targets.
- Proposed per-validation limits: 200 KiB UTF-8 source, three seconds wall time, bounded CPU, and approximately 128 MiB subprocess memory. Confirm practical limits with fixtures before shipping.
- Treat timeout, worker crash, dependency absence, and compilation errors as distinct non-valid results. Never mark a rule valid when the validator could not run.
- Limit concurrent validations across workers through a small database-backed capacity/lease mechanism; no paid worker pool is required.

All reports state: **syntax/structure validation is not proof of detection efficacy**.

## 6. Proposed API and authorization

| Route | Access / behavior |
| --- | --- |
| Existing `GET /api/detection-rules` and `/{id}` | Authenticated readers receive published/legacy-public content only; analysts/admins can explicitly request authorized working data |
| Existing `POST /api/detection-rules` | Analyst/admin; create draft identity and first revision |
| `POST /api/detection-rules/{id}/revisions` | Analyst/admin; create immutable revision with expected parent/version |
| `GET /api/detection-rules/{id}/revisions` and `/revisions/{revision_id}` | Analyst/admin; complete history; public readers cannot enumerate private draft IDs |
| `POST /api/detection-rules/{id}/revisions/{revision_id}/validate` | Analyst/admin; bounded validation, explicit result |
| `POST .../submit`, `POST .../withdraw` | Analyst/admin; valid transition and current candidate required |
| `POST .../review` | Human admin, not the candidate author; approve/reject with rationale |
| `POST .../publish` | Human admin; matching validated hash, approval, and expected current version |
| `POST /api/detection-rules/{id}/rollback` | Analyst/admin; create a new draft from a prior revision |
| `POST /api/detection-rules/{id}/archive` | Admin; preserve history |
| `GET /api/detection-rules/{id}/download` | Return the authorized published/legacy snapshot with revision/hash metadata; never the latest private draft by default |

Machine analyst/admin tokens may create drafts or request validation, but cannot satisfy independent human review or publish. The public HTML catalog must query an explicit public read model before rendering; no draft source, counts, hidden templates, or validation details may leak.

## 7. UI and implementation map

- Extend `rule_service.py`; add `rule_validation_service.py`, `rule_lifecycle_service.py`, revision/review schemas, and protected lifecycle routes.
- Update `rules.html`; extract its growing editor logic into `app/static/js/rules.js` without introducing a frontend build system.
- Add tabs/panels for source, validation, revision diff/history, review comments, and deployment guidance.
- Show badges for legacy/unreviewed, draft, validation error, pending review, and published revision. Downloads identify their exact revision.
- Render diffs/source as escaped text; untrusted Markdown must not become executable HTML.

## 8. Staged implementation

1. **Migration/read models:** preserve existing identities/content; backfill unreviewed snapshots; separate public and authoring queries. Exit: guests cannot see any newly created draft.
2. **Versioning/concurrency:** append revisions, parent/version checks, readable diffs, archive semantics, and rollback-to-new-draft behavior.
3. **Validators:** pinned dependencies, subprocess limits, safe parsing/compilation, per-worker coordination, and deterministic reports tied to source hashes.
4. **Review/publication:** explicit transitions, independent reviewer checks, stale-candidate protection, transactionally audited publication.
5. **UI/review:** complete draft → validate → review → publish → rollback demonstration, Docker dependency tests, accessible UI, and documentation of legacy content/limitations.

## 9. Tests and acceptance criteria

- Valid/invalid Sigma and YARA fixtures, invalid UUIDs/selector references, unsafe YAML, include-path attempts, oversized/deeply nested input, subprocess timeout/crash, and missing validators are covered.
- Updating source/metadata cannot preserve an approval or validation result from a different hash.
- Self-approval, machine-token approval/publication, invalid transitions, and publishing a stale candidate are rejected.
- Concurrent submissions/publications cannot create duplicate revision numbers or lose the current published pointer.
- Viewers/guests see the old published revision while a new draft exists; detail, catalog counts, hidden DOM, downloads, and exports obey the same rule.
- Rollback creates a new reviewed revision; neither rollback nor archive erases earlier evidence.
- Seeded examples that fail validation remain visibly unreviewed/invalid; tests do not weaken the validator to make demonstrations pass.
- Proposed F1 budget: 50 revisions per rule and 50 MiB total retained rule snapshots initially. On reaching a limit, reject with an actionable export/archive message—do not silently prune audit history.
- Existing catalog filters/themes still work, and no paid hosting or validation service is introduced.

## 10. Rollout, recovery, and later choices

Use `FEATURE_RULE_LIFECYCLE`. Legacy-content visibility and the changed update/delete contract must be documented before enabling it. After versioned writes begin, turning the feature off should preserve a **read-only published catalog**, not reactivate the old mutable CRUD paths and bypass review.

**Recommended defaults to approve:** unreviewed legacy visibility, independent human admin approval, no direct deployment, local-only validators, and strict source/report limits. SIEM conversion and efficacy testing require a later, separately scoped set of log fixtures and platform-specific acceptance tests.
