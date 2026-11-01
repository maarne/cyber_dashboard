# Feature 1 validation record

Validated locally on 2026-11-01. No cloud deployment/provisioning was performed.
The workspace's existing `cyber_dashboard.db` was not used by these checks.

## Automated checks

- `python -m scratch.run_tests`: all isolated suites passed, including Feature 1
  coverage for migration upgrades/repeated startup/rollback, private routes and
  role permissions, accurate API explorer metadata, CSRF/session/origin checks,
  explicit machine authentication, optimistic concurrency, audit rollback,
  CSV validation/preview/commit/merge/token binding, exports, quotas, missing/zero/
  maximum scores, urgent KEV ordering, EPSS timestamps, stale intelligence,
  archive/restore, and risk-acceptance expiry.
- Existing authentication, intelligence, detection-rule, audit, UI/theme, SSRF,
  setup, backup, and F1-only configuration regression suites passed unchanged.
- `docker build -t cyberdash:asset-prioritization .`: succeeded.
- `python -m scratch.container_smoke cyberdash:asset-prioritization --assets`
  and the same command without `--assets`: passed, exercising non-root runtime,
  two workers, migrations, health, login, token rate limits, audit concurrency,
  feature-off behavior, CSRF, unknown-score queue, concurrent inventory edits,
  and local-volume retention across container replacement. Disposable smoke
  containers/volumes were removed by the test.
- `git diff --check` and local Markdown link validation passed.

The environment has no `node` executable, so `node --check` was unavailable.
The UI JavaScript was instead executed and checked in the in-app Chromium browser.
Existing dependency deprecation warnings remain; no dependency was added or
changed for this feature.

## Browser checks

Used an isolated, localhost-only preview with disposable setup credentials and
synthetic inventory; outbound provider access was blocked by the test fixture.
Verified:

- Setup/login → create asset → add software → associate CVE.
- Unknown complete score with known subtotal, component/evidence explanation,
  and missing/freshness warnings.
- Assessment edit/remediation, preserved history, and removal from the default
  actionable queue while remaining visible in all-state results.
- CSV file preview, explicit commit, and resulting inventory/queue rows.
- Form colors inherited all six existing themes; the queue did not overflow the
  desktop viewport. The shared button CSS initially overrode `hidden`; a scoped
  fix now keeps the import confirmation hidden until a valid preview exists.
- No browser console errors during the checked workflow.

## Bounded-data measurement

Repeat with `python -m scratch.benchmark_asset_prioritization`. The isolated
fixture contains 500 assets, 10,000 assessments, and 4,000-character evidence per
assessment. Five queue calls return a 50-row page:

| Measurement | Observed local result |
| --- | --- |
| Queue median | 0.361 seconds |
| Queue peak traced Python allocations | 24.42 MiB |
| Benchmark process resident memory before tracing | 75.20 MiB |
| 1,000-row CSV parsing | 0.056 seconds |

Only the selected page's evidence/reasons are hydrated. These are local service
measurements, not Azure F1 latency, whole-server/two-worker memory, a concurrent
load test, or an uptime/capacity guarantee. Archive/audit history and other feeds
still consume SQLite storage; operators must monitor and back up their database.

## Rollout boundary

Feature 1 remains disabled by default until the operator sets its environment
flag and restarts. Back up before the first startup migration. F1-only guards,
disabled Always On, and intentionally ephemeral Azure storage are unchanged.
Features 2–5 remain unimplemented and require separate approval.
