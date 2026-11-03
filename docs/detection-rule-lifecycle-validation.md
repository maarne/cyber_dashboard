# Feature 3 validation handover

Validated locally on 2026-11-02. See [operation/privacy/recovery](detection-rule-lifecycle.md).

## Passed

- Full isolated `python -B -m scratch.run_tests`, including **20 lifecycle tests**,
  existing asset/network/case/security suites and F1-only configuration guards.
- Real pySigma/PyYAML parsing and native YARA compilation; valid/invalid source,
  invalid UUID/status/selector references, duplicate/multi-document/tagged/aliased/
  deeply nested YAML, YARA include/module attempts and inert string literals.
- Version-3 → version-4 additive migration and transaction rollback; exact legacy
  null/whitespace/content and stable IDs; idempotence and foreign-key checks.
  Existing over-quota catalogs remain readable rather than silently truncated.
- Privacy on catalog/detail/search/download/history/exports, analyst/admin RBAC,
  cookie CSRF/origin, machine-token restrictions and untrusted HTML escaping.
- Missing validation, self-review, stale parent/version/policy, reviewer demotion,
  tampered snapshots and invalid transitions reject publication. Concurrent
  publication produces one success/one 409; audit failure rolls back publication.
- Shared validation slots, expired claims, per-revision/global quotas, report/audit
  rollback, timeout/crash/output overflow and blocked child stdin. A blocked input
  pipe cannot escape the three-second wall deadline. Missing dependency is non-valid.
- Withdrawal/rollback creates another private draft without inherited review/report;
  private successors never replace the old public revision. Archive retains history.
- History export uses a consistent transaction and still works when the domain-event
  quota is full; it appends a security audit event rather than consuming domain quota.
- CPython 3.11 Linux Docker build using binary wheels, no runtime compilers, non-root
  UID 10001, two Gunicorn workers. Smoke modes passed on the final application image:
  `--rules`, `--rules --cases --network`, and all flags off. Container replacement
  retains data and the activation latch; flag-off never restores mutable CRUD.
  Both Sigma and YARA fixtures also validated in the final Python 3.11 image with
  Docker networking disabled.
- Isolated Chromium workflow: author draft → native validation → submit → different
  human-admin approval → publish → private successor → source/metadata diff → rollback
  draft. Old public source remains unchanged; rollback has no inherited validation.
  No browser console errors. All six themes had no desktop horizontal overflow.
- Pinned environment `pip check`: no broken requirements. Only existing FastAPI/
  httpx TestClient deprecation warnings were observed; tests pass.

## Reproduce with disposable data

```bash
python -B -m scratch.run_tests
python -B -m scratch.measure_rule_lifecycle
docker build -t cyberdash:rule-lifecycle .
python -B -m scratch.container_smoke cyberdash:rule-lifecycle --rules
python -B -m scratch.container_smoke cyberdash:rule-lifecycle --rules --cases --network
python -B -m scratch.container_smoke cyberdash:rule-lifecycle
python -B -m scratch.preview_rule_lifecycle
```

The preview uses disposable synthetic accounts/source at `http://localhost:8768`.
It is not the live database. Stop it after testing; do not reuse demo credentials
for real accounts. Tests do not scan files, deploy rules or scan real networks.

## Local synthetic measurements

Fixture: **500 identities, 985 revisions, 48,739,911 retained snapshot bytes**,
including 485 new identities with two roughly 50 KiB revisions each. Built through
service mutations (110.04 seconds). Five-read median timings:

| Operation | Local milliseconds |
| --- | ---: |
| Private working page (20 identities) | 9.41 |
| Public catalog (15 legacy entries, private identities excluded) | 5.26 |
| Sigma fixture validation (three-run median) | 299.20 |
| YARA fixture validation (three-run median) | 229.28 |

History query used `idx_rule_revisions (rule_id=? AND id<?)`. Observed Linux
child-process high-water RSS was 64,920 KiB across this measurement process;
this includes launcher/exec accounting, not a guarantee of steady-state RSS.
The final image was 232,980,664 bytes locally (uncompressed Docker size).

These local fixtures do **not** establish F1 latency, native-parser security,
maximum web-worker concurrency, full worst-case export performance or uptime.
Payload/index/audit overhead, two concurrent validators and web workers share the
host's memory/CPU; keep operator budgets conservative. No paid capacity was added.

## Existing-instance rollout: blocked, not enabled

The old 8765 app was already down at Feature 3 start. On rollout preflight,
`/tmp/opencode/cyberdash-runtime-8765-s6zgpfjr/settings.json` and `dashboard.db`
were absent, and `/tmp/opencode` was empty. The previously recorded pre-case
backups in that same temporary directory were absent too. No 8765 listener existed.
Searches of the temporary area, workspace parent and OpenCode data area did not
locate that runtime database/settings backup. A workspace-root database is **not**
assumed to be an equivalent replacement.

Therefore **no live migration, activation, restart, validation, review or publication
was performed**. No replacement signing key, accounts or demo data were created
for the live app, and no existing workspace database was modified by testing.
The isolated 8768 preview was stopped after checks.

To complete rollout, restore/provide the saved runtime database and private settings
(including its original signing key) from a durable backup. Do not paste secrets
into chat. Then take a new consistent backup, enable only the new lifecycle flag,
restart the same 8765 app, and verify schema versions `[1,2,3,4]`, old rule IDs/
content, accounts/assets/cases/network settings and the legacy warning. Leave real
rule validation/publication and any reviewer-account creation as explicit user actions.

Changes are uncommitted. Default-off configuration and RFC1918-default asset scope
are unchanged. No cloud deployment, paid infrastructure, new provider accounts,
commit or push was introduced. Features 4–5 were not started.
