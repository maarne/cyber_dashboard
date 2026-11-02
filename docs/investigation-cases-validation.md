# Feature 2 validation handover

Validated locally on 2026-11-02. See [operating/privacy guidance](investigation-cases.md).

## Passed

- Full isolated regression run: `python -B -m scratch.run_tests`, including 21
  new case tests, existing asset/network/security suites and F1-only guards.
- Additive version-3 upgrade, idempotence and transaction rollback; legacy history
  retains unknown actor/no-snapshot attribution rather than fabricated evidence.
- Role/privacy/CSRF checks, principal-bound unattached captures, shared-case access,
  real service-token attribution, deleted-assignee preservation and export guards.
- Atomic audit failure rollback, stale edits and concurrent evidence deduplication.
- Local-only capture, source availability, unchanged saved results, tamper warnings,
  append-only corrections, required closure conclusions and reopen history.
- Docker build and non-root two-worker smoke tests: case-only operation without
  assets, combined case/asset/network flags, and feature-off behavior. Data and
  evidence persist across disposable container replacement.
- Chromium isolated workflow: local-only EICAR capture → case → note → close →
  export → reopen → attach another capture → compare. No application console errors.
- All six themes checked; responsive header wrapping prevents desktop overflow.
- Documentation links and `git diff --check` passed.

## Local synthetic measurements

Fixture: 200 cases, 1,000 snapshots totaling 50,302,890 payload bytes. The largest
case had 25 snapshots and 200 notes of 8,000 characters each.

| Operation | Seconds | Output bytes |
| --- | ---: | ---: |
| List 50 cases | 0.0073 | — |
| Read 10 evidence records | 0.0160 | — |
| Largest-case JSON export | 0.1340 | 2,931,520 |
| Largest-case Markdown export | 0.2368 | 4,563,360 |

The case filter query used `idx_cases_status`, with a bounded temporary sort for
ID ordering. These are local synthetic read/export measurements, not F1 latency,
concurrency capacity or uptime promises. No provider traffic was needed.

## Existing local instance

Enabled `FEATURE_CASE_MANAGEMENT` on the existing port-8765 app after a consistent
private pre-upgrade database/settings backup. Migration versions are now 1, 2, 3.
Preserved the signing key, accounts and all existing network settings/configurations.
At rollout verification, preserved counts were: one user, 17,140 CVEs, one asset,
one discovery profile, one monitor configuration, zero lookup-history entries
and 23 audit entries. No synthetic cases/captures were inserted into that database.

Health/readiness passed; unauthenticated case/snapshot routes correctly return
401/no-store. An existing authenticated browser session could open the new empty
case list, without console errors or horizontal overflow. The isolated preview
on 8767 was stopped; the updated 8765 app remains running.

Code defaults remain feature-off. No new provider accounts, paid infrastructure,
cloud deployment, dependencies, commit or push were introduced. Features 3–5
were not started. No IOC enrichment or asset scan was triggered for live testing.
