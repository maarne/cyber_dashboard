# Feature 1A/1B validation handover

Initial implementation validated locally on 2026-11-01. See [operating guidance](asset-network-operations.md)
for authorization, configuration, limitations and restore procedures.

## Passed checks

- All isolated suites via `python -B -m scratch.run_tests`, including 19 new
  monitoring/discovery tests and existing inventory, scoring, security and F1 tests.
- Additive migration, rollback, permissions/CSRF, destination restrictions, shared
  claims/budgets/locks, cancellation, partial rotation and stale-result rejection.
- Selective atomic import/link, conflict/audit rollback, changed-name review and
  retained evidence surviving transient observation deletion.
- Docker builds with and without optional utilities; non-root two-worker smoke
  checks, restart persistence, and empty-scope traffic denial in both variants.
- Real HTTP/TCP/ICMP adapters and discovery against disposable container loopback
  fixtures with `--network none`; no production self-address exception added.
- Chromium mocked workflow: seven-minute profile, selected-row preview/commit,
  preserved evidence, simulated availability check and availability filtering.
- All six themes checked for input styling; no desktop horizontal overflow.
- `git diff --check` and local Markdown documentation links validated.

## Measurements (not throughput or uptime guarantees)

- 100 scheduled mocked checks: 21.306 seconds for scheduling/results bookkeeping.
  SQLite durability dominated measured execution time.
- Authorized 4,096-address range enumeration: 0.265 seconds, 4,093 eligible hosts.
- Docker images: 235.13 MiB with optional tools, 205.88 MiB without.
- Loopback fixture tools: curl 7.88.1, nmap 7.93, iputils 20221126; UID 10001,
  no ping setuid/setgid or file capability.

## Local rollout boundary

The existing app on port 8765 was updated with migration versions 1 and 2.
Its signing key and existing records were preserved: one user, 17,140 CVEs,
zero assets and six audit entries at rollout verification. A consistent private
pre-upgrade database/settings backup was retained beside the runtime database.

Monitoring/discovery configuration UI is enabled for this local instance, but
the operator CIDR allowlist was empty at that initial handover. No monitor configurations, discovery
profiles or network jobs were created in that instance. Code defaults remain off.
No real asset networks were authorized or scanned, no host tools were installed,
and no cloud deployment, paid infrastructure, commit or push was performed.

## RFC1918 default update (2026-11-02)

At the user's request, an unset destination allowlist now permits the three
RFC1918 IPv4 ranges. Explicit lists replace those defaults; an explicitly empty
value still denies all targets. Feature flags and per-check/profile opt-in remain
unchanged. Self/metadata/special-address denials and scan size limits still apply;
public IPs and IPv6 ULA remain outside the default scope. No real scans are part
of this update.

The 21 isolated network tests passed, including the unset/default, explicit-list
replacement and explicit-empty cases, RFC1918 boundary addresses, mapped IPv4,
DNS answer restrictions, retained hard denials, scan-size limits and opt-in checks.
The existing 8765 instance was restarted after removing its previous empty
override. Health/readiness passed; its database/signing key and one disabled
discovery profile were preserved. No configurations were enabled or jobs created.
The complete isolated regression run (`python -B -m scratch.run_tests`) also
passed after the RFC1918-default change, including existing security/SSRF checks.
