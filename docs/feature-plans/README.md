# CyberDash feature implementation plans

**Status:** Feature 1 implemented following user approval; Features 2–5 remain planning only.  
**Created:** 2026-11-01.  
**Baseline:** the current FastAPI/SQLite application after the security fixes and F1-only configuration.

## 1. Roadmap and recommended order

Implement **one complete feature at a time**, review its acceptance results, and obtain approval before starting the next. The order below is recommended, not mandatory.

| Order | Plan | Usable outcome | Relative complexity |
| --- | --- | --- | --- |
| 1 | [Asset-aware prioritization](01-asset-aware-prioritization.md) — implemented, default off | An inventory and explainable queue of vulnerabilities affecting your systems | Medium–large |
| 2 | [Investigation case management](02-investigation-case-management.md) | Owned cases with notes, preserved evidence, dispositions, and exports | Medium–large |
| 3 | [Detection-rule lifecycle](03-detection-rule-lifecycle.md) | Validated, versioned rules with independent review and controlled publishing | Large |
| 4 | [Personalized watchlists](04-personalized-watchlists.md) | Saved monitoring criteria, in-app alerts, controlled webhooks, and digests | Large |
| 5 | [Enterprise authentication](05-enterprise-authentication.md) | Optional OIDC SSO, local TOTP MFA, recovery, and safe identity linking | Large; security-sensitive |

Complexity describes integration and testing scope, **not an implementation-time estimate**.

### Feature 1 extensions awaiting approval

[Feature 1A — Configurable asset availability checks](01a-asset-availability-monitoring.md)
adds a proposed per-asset IP/hostname, selectable standard-utility checks,
Up/Down/Unknown/Stale status, manual checks and optional bounded scheduling.

[Feature 1B — Multi-network discovery and selective import](01b-network-discovery-and-selective-import.md)
adds proposed multi-network scan profiles, hostname discovery, custom recurring
intervals (seconds/minutes/hours/days), a candidate staging list, and quick
preview/confirm import of selected assets. Requested frequency is separate from
actual capacity, with non-overlapping scans and visible deferred/partial work.

This is planning only: no probes, system tools, network permissions, or runtime
changes have been added. It does not start Features 2–5 or change risk scoring.

### Dependencies

- Feature 1 uses current CVE/KEV/EPSS ingestion; it does not require a paid inventory/scanning service.
- Feature 2 uses the existing IOC investigator and can reference current assets and rules. Asset references are optional if Feature 1 is deferred.
- Feature 3 operates independently; case-to-rule references resolve stable rule identities, not mutable code.
- Feature 4 starts with existing CVE/KEV data. Asset filters and published-rule subscriptions are optional extensions after their respective features exist.
- Feature 5 does not require the other features. Implement it earlier if authentication is the immediate priority; keep stable internal user IDs in every earlier feature to make later SSO linking safe.

## 2. Non-negotiable constraints

1. **No paid infrastructure:** retain F1-only Bicep guards, no Always On, no paid storage/database/queue, no billable cron or authentication service provisioned automatically.
2. **No uptime or durability promises on F1:** the app can sleep, scheduled tasks can be missed, and a replaced container can lose SQLite data. Exports/backups are essential; use a local Docker volume for development that needs persistence.
3. **Keep the stack:** FastAPI, SQLite, Jinja2, vanilla JavaScript/CSS. No frontend framework, bundler, Redis, Celery, Kubernetes, or vector database is required.
4. **Truthful intelligence:** missing facts stay unknown. Product-name similarity is not proof of vulnerability; a pivot URL is not evidence that a provider was queried.
5. **Protect existing work:** additive migrations, stable IDs, no silent reseeding over user edits, no automatic historical deletions, and no live-database test execution.
6. **Keep current security fixes:** explicit signing secrets, revocable sessions, enforced token limits, public-address-pinned outbound requests, masked webhook URLs, and versioned audit verification.
7. **Approval boundaries:** Feature 1 was approved and implemented behind a default-off flag. Tables, routes, dependencies, and settings in Features 2–5 remain proposals; implementation requires separate approval.

## 3. Shared implementation conventions

These are small prerequisites introduced **inside the first feature that needs them**, not a separate application rewrite.

### Identity and authorization

- Enrich authenticated request context with canonical `user_id` for human sessions and `token_id` for machine tokens. Do not infer identity by parsing `username` or an `api:` prefix.
- Ownership and assignment use internal user IDs. Preserve an actor display-name snapshot in historical events; deleting a user must not delete case evidence or rule history.
- Personal resources require a human principal unless an explicit machine-ownership model is approved. Role alone does not grant access to another person's private watchlists.
- Add narrowly scoped authorization helpers rather than weakening existing admin/analyst/viewer checks. Check HTML routes, APIs, exports, counts, and background jobs—not only buttons.
- Browser-cookie mutations require CSRF protection and trusted-origin checks. Explicit API-key/Bearer calls are handled separately. Do not introduce new state-changing GET routes.

### Database and audit

- Add a small migration-version ledger and apply ordered, idempotent changes under the existing startup write lock. Test upgrades from an existing database, not just empty initialization.
- Use SQLite foreign keys, `CHECK`/unique constraints, indexes, short transactions, and bounded/paginated queries. Do not introduce WAL assumptions on an unverified remote filesystem.
- Use `row_version`/`expected_version` for editable records; return **409** for stale updates. Document validation, not-found, authorization, and size-limit responses.
- New domain mutations and their audit events should commit atomically. Extend the audit append helper to accept the caller's existing transaction; **do not call the current independently locking logger while holding another write transaction**.
- Schema rollback is not destructive down-migration: disable the feature and preserve its tables. Use a verified backup for a full restore; do not claim old application versions automatically understand new schema.

### UI and services

- Put business logic in focused `app/services/` modules; routes validate and authorize. Use new route modules if needed without making a whole-project router refactor a prerequisite.
- Reuse existing layouts, themes, forms, modals, and toasts. Keep keyboard access, labels, error messages, loading states, and empty states consistent.
- Treat titles, notes, CSV values, rule source, and identity-provider claims as untrusted. Use text nodes/data attributes, safe YAML loading, bounded JSON, and safe exports.
- Add explicit request/response schemas. New routes should appear correctly in OpenAPI and the existing API explorer.

### Free-tier operating budgets

- Prefer indexed SQLite queries and cached local facts over extra provider calls per page load.
- Enforce proposed per-feature size/count limits and display limits clearly. Measure on test fixtures before finalizing them; proposed limits are not performance guarantees.
- Background work uses persisted checkpoints/leases shared by the two web workers. No unbounded scan or long write transaction in the scheduler's polling loop.
- Feature-off behavior leaves current routes and workflows usable. Missing optional dependencies/settings must not break application startup unless that feature is explicitly enabled.

## 4. Common delivery gate for each feature

1. **Approve scope:** confirm the recommended defaults, dependencies, and any genuinely blocking decisions in that feature's plan.
2. **Design contract:** finalize schema, APIs, permissions, error cases, and migration behavior; write acceptance fixtures first.
3. **Backend slice:** implement migrations, services, authorization, audit events, and service/API tests before wiring the UI.
4. **UI slice:** add a complete user workflow, with no hidden/unauthorized data embedded in pages or JSON.
5. **Verify:** add isolated suites under `scratch/`; run `python -m scratch.run_tests`, browser checks, migration tests, Docker build/smoke tests when runtime changes, and F1 configuration regressions.
6. **Resource check:** test realistic bounded datasets, query plans, and two-worker contention. Record measured results instead of asserting the app is scalable.
7. **Handover:** document new settings, limits, export/recovery instructions, known limitations, and a small demonstration workflow.
8. **Stop:** summarize results and obtain approval before the next feature. Do not deploy, purchase, configure external accounts, or change hosting tiers as part of feature completion.

## 5. Cross-feature contracts

| Contract | Decision |
| --- | --- |
| Identifiers | Existing CVE strings and stable integer asset/case/rule IDs; revision and snapshot IDs identify immutable content |
| Time | UTC in storage/API; local display may be derived in the browser |
| Risk | Priority, IOC verdict, case disposition, and rule severity are separate concepts |
| History | Preserve what was known at capture time; a refreshed feed must not silently rewrite case evidence |
| Notifications | At-least-once network delivery with deduplicated enqueueing; never promise exactly-once webhook delivery |
| Credentials | User passwords, provider tokens, MFA secrets, and webhook secrets never enter exports or audit details |
| Exports | Versioned schemas, safe CSV cells, no automatic import of secrets, and no implication that exports replace off-host backups |
| Development data | No real customer evidence, production credentials, or malware samples in seeded/demo/test data |

## 6. Decisions already recommended

- Start Feature 1 with **manual and CSV inventory plus explicit CVE associations**, not unreliable automatic version matching.
- Start Feature 2 with **team-visible analyst/admin cases**, no file attachments and no public report links.
- Start Feature 3 with **admin review by someone other than the author**; use two local accounts to test the workflow at zero extra service cost.
- Start Feature 4 with **private human-owned CVE/KEV watchlists and in-app alerts**. Webhooks are optional and require admin-granted destinations.
- Start Feature 5 with **local TOTP MFA**, then add one optional standards-based OIDC provider. Free testing must not rely on paid identity-policy features.

The remaining product choices are called out in each individual plan. They do not authorize additional infrastructure spending.
