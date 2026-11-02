# Feature 1A — Configurable asset availability checks

**Status:** implemented following approval; disabled by default, RFC1918 destination scope by default.
**Parent:** [Feature 1 — Asset-aware prioritization](01-asset-aware-prioritization.md).  
**Goal:** show whether an explicitly configured IP/hostname responds to a selected check, from the CyberDash runner's network.

This is an optional extension of Feature 1, not the start of Features 2–5.
Implementation was approved. Permission to contact real targets remains separate.

The requested multi-network discovery and fast selective-import workflow is
planned in [Feature 1B](01b-network-discovery-and-selective-import.md). Discovery
stages candidates separately; it does not silently create assets or enable/
retarget this feature's per-asset monitors. Both plans share safe network scope,
capacity controls and configurable scheduling infrastructure.

## 1. Baseline and boundaries

The current inventory has no dedicated target address, availability state, or
probe configuration. Its routes deliberately do not contact assets. The existing
outbound client permits only public destinations and must remain that way for
RSS, intelligence providers, and webhooks.

The container runs as a non-root user and does not currently install `curl`,
`ping`, or `nmap`. The feed scheduler can block while refreshing upstream data,
so availability jobs cannot simply run synchronously in that same loop.

### Include

- One optional IP address or hostname and **one primary check per asset**.
- Per-asset utility/type, service port or HTTP settings, manual/scheduled mode,
  timeout, interval, and failure threshold.
- Inventory badges, detail/history, last successful/failed observation, latency,
  freshness, and clear diagnostics when a check cannot run.
- Manual **Check now** and optional best-effort periodic checks.
- Existing authentication, CSRF protections, audit attribution, concurrency
  checks, quotas, and default-off rollout behavior.

### Exclude

- Subnet discovery **inside the per-asset check** (see Feature 1B for the separate
  discovery workflow), port ranges, service/OS/version detection, vulnerability
  scanning, NSE scripts, remote commands, authenticated SSH, passwords/private
  keys, arbitrary command lines, agents, and automatic remediation.
- Combining multiple checks into an unexplained asset-wide health verdict.
- Alerts/webhooks, uptime/SLA percentages, a new paid scheduler, or guaranteed
  monitoring while F1 sleeps. Notifications remain a separate Feature 4 concern.

**No vulnerability score changes:** a failed availability check does not prove
an asset was retired, remediated, patched, or no longer exposed. Preserve CVE
assessments, business criticality, exposure, and the current ranking formula.

## 2. Recommended standard utilities

| Per-asset check | Utility / restricted behavior | Success means |
| --- | --- | --- |
| HTTP / HTTPS | `curl`, fixed adapter, one configured HEAD/GET health request | A verified HTTP response matches the configured status-code policy |
| ICMP | Linux `iputils` `ping`, one numeric destination and one echo request | An ICMP echo reply was received |
| TCP service | Optional `nmap`, unprivileged TCP connect to exactly one numeric IP and one port; DNS, discovery, scripts and version detection disabled | The configured port accepted a TCP connection |

Recommend **curl for web services**, ping only when ICMP works in the deployment,
and single-port nmap for other services. An SSH-server preset uses TCP port 22:
label it **SSH port reachable**, not “SSH login verified.” Do not run `ssh` or
attempt credentials/commands. A future actual SSH-handshake adapter, such as
restricted `ssh-keyscan`, would need its own approval and tests.

These utilities are adapters, not editable commands. Install only the approved
packages; make nmap an explicit optional capability. During implementation,
record utility versions, image-size/security impact, supported flags, licensing,
and timeout behavior. No tool is installed or invoked as part of this plan.

### HTTP-specific rules

- Store the host/IP separately from scheme, port, and bounded relative health
  path; do not accept a complete arbitrary URL or user-supplied headers.
- Default: HTTPS, port 443, HEAD `/`, expected status 200–399. Permit explicit
  HTTP, alternate port, GET health path, and a validated status-code list/range.
  GET is opt-in for an operator-approved, non-mutating health endpoint; even a
  nominally read-only method is not a guarantee of safe behavior on every server.
- Do not follow redirects. A redirect can meet the configured response policy
  but says nothing about the destination. A 401/403/405 can show that HTTP
  responded while still failing the configured service check; offer explicit
  expected-code configuration instead of silently guessing a fallback method.
- Require normal TLS certificate/hostname verification. No insecure-TLS toggle
  in v1. With an IP target, a hostname certificate mismatch is a failed HTTPS
  check; configure the appropriate hostname instead.
- Discard response bodies, bound headers/output, and store only selected safe
  metadata: response code, timings, verification outcome, and safe error code.
  Do not store cookies, authentication challenges, arbitrary headers, or bodies.

### Capability checks

Report utility availability and supported modes without contacting assets.
If ICMP is blocked by container/kernel permissions, show **Unknown — ICMP not
supported here**. Missing tools/permissions are not asset failures. Do not run
the web app as root, add privileged containers, or automatically grant raw-socket
capabilities. HTTP/TCP remain usable when ping is unavailable.

## 3. Per-asset configuration and workflow

Example configuration:

| Setting | Example / proposed default |
| --- | --- |
| Target | `web01.example.net` or one IPv4/IPv6 address; never inferred from external ID |
| Enabled | Off until an administrator explicitly saves and enables the check |
| Primary check | HTTPS (`curl`); selectable ICMP or optional single-port TCP |
| Port | 443 for HTTPS, 80 for HTTP, explicit 1–65535 for TCP; none for ICMP |
| HTTP method/path | HEAD `/`; explicit GET health endpoint when appropriate |
| Expected HTTP codes | 200–399, configurable within a bounded validated schema |
| Execution mode | Manual only initially; scheduled mode is explicit opt-in |
| Scheduled interval | 15-minute default; custom positive whole-second interval with seconds/minutes/hours/days units, not preset-only |
| Probe timeout | 3 seconds by default, configurable 1–5 seconds |
| Failure threshold | Three consecutive completed negative observations; configurable 1–5 |
| Recovery threshold | One successful completed check |
| Manual-result freshness | 15 minutes |

1. An administrator enters the target and selects a check on the asset detail page.
2. The UI shows the runner/network perspective, allowed destination scope,
   available utilities, traffic/time limits, and authorization acknowledgement.
3. Saving validates configuration and applicable static policy but does **not**
   resolve DNS or contact the target. Address authorization for a hostname is
   checked when a job runs. The administrator explicitly enables the monitor
   and requests a first check.
4. An authorized analyst/admin can run **Check now** for that saved configuration.
   The request is queued and returns a job ID, not a blocking subprocess result.
5. A worker executes the bounded check; the UI shows its result and freshness.
6. Optional scheduling collects later observations while the application runs.

Changing target/method/settings increments a configuration generation and resets
failure streak/freshness. Old history remains labeled with its old configuration.
Disabling or archiving cancels pending work and hides a current “Up” badge;
restoring an asset does not silently resume network checks. Require explicit
re-enablement. Do not accept monitoring settings through the current version-1
inventory CSV; an inventory import must never arm probes or retarget a monitor.

## 4. Truthful Up / Down / Unknown semantics

Keep execution state, raw observations, and displayed availability separate:

- **Up:** the configured check succeeded recently from this runner.
- **Down:** the configured check met its consecutive-failure threshold. This
  means “not responding as configured from CyberDash,” not “powered off.”
- **Unknown / not checked:** no current-generation observation exists.
- **Unknown / error or blocked:** missing utility, denied permission, policy
  rejection, unsupported address family, failed DNS resolution, worker failure,
  or a local routing/configuration problem prevents a reliable measurement.
- **Stale:** a previously measured Up/Down result is too old. Display the last
  known result and time, but do not present it as current availability.
- **Disabled:** no checks are enabled. This is not Down.
- **Queued / checking:** an execution overlay, not a new availability verdict.

Completed target timeouts, connection refusals, closed TCP ports, HTTP status
mismatches, and peer TLS verification failures are negative observations under
their selected check. Unknown/error outcomes break the failure streak rather
than turning a monitoring failure into a host outage. For ICMP, distinguish an
echo timeout from tool/permission errors; do not assume every nonzero exit is Down.

One or two negative observations after Up show a visible **check failing — 1/3**
warning while the recent prior stable result remains available. Before the first
success/threshold, display **Unknown — awaiting confirmation**, not Up. At a
15-minute interval, three failed scheduled checks can take roughly 30–45 minutes
to confirm a failure, plus queue delays; always expose the latest raw result.

Proposed scheduled freshness deadline: two intervals plus the total job timeout,
measured from the latest current-generation completed positive/negative
observation. Queued jobs and inconclusive/local-error outcomes do not renew it.
If a job is late, the runner disappears, or F1 sleeps, elapsed time yields Stale,
not fabricated downtime or extra failed samples. Manual mode uses its 15-minute
TTL. History is observation history, not continuous uptime or proof of compromise.

## 5. Target authorization, SSRF, and command safety

This extension intentionally introduces network contact, including legitimate
internal assets. It must use a **separate restricted probe transport/policy**;
never relax `app/services/outbound_service.py` or its public-only rules.

### Administrator-approved destination scope

- Operator setting: `ASSET_PROBE_ALLOWED_CIDRS`. Following the RFC1918-default
  request, unset permits `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
  An explicit list replaces those defaults; an explicit empty value means no
  probing. Require resolved destinations to be inside that scope. Reject
  universal IPv4/IPv6 `/0` allowances. Network scope is operator-controlled,
  not an analyst-editable inventory field or arbitrary request parameter.
- Public and RFC1918/IPv6-ULA assets can be checked only when their resolved IPs
  satisfy that policy. Entering a hostname/IP is not proof of ownership; require
  an administrator acknowledgement that the organization authorizes the checks.
- Always deny loopback, unspecified, link-local, multicast, broadcast, reserved
  special-use addresses other than in-scope RFC1918/explicitly authorized ULA networks,
  cloud metadata/platform control endpoints (including
  Azure's platform virtual IP), and the runner's own addresses. These denials
  override allowlists. Explicit private-network permission is not a metadata or
  localhost exception. Normalize IPv4-mapped IPv6 before classification.
- Accept one canonical IP or valid bounded DNS hostname. Reject CIDR/list/range
  targets, URL schemes, credentials, path/query fragments in the target field,
  control characters, scoped IPv6, option-like inputs, and shell metacharacters.

### DNS and execution

- Resolve immediately before every execution, never on page load or configuration
  save; validate **all** answers and reject mixed permitted/prohibited answers. Bound
  DNS time and address count (proposed maximum eight). DNS work itself must be
  cancellable/time-bounded, not an indefinitely blocked resolver thread.
- Pin one approved numeric IP per attempt; never let the utility independently
  resolve the original hostname. Preserve hostname/SNI verification for curl via
  its fixed host-to-address binding. Record address family and chosen address;
  v1 does not claim all addresses behind a hostname are reachable.
- Use approved absolute executable paths and fixed argument arrays with
  `shell=False`; never interpolate user data into a command string. No shell,
  executable selector/path, arbitrary flags, environment overrides, or scripts
  can be supplied by a browser/API request.
- Disable curl configuration files, proxies/environment proxy inheritance,
  redirects and non-HTTP protocols. Use nmap only with fixed unprivileged TCP
  connect, no ping discovery, no DNS, one port, and bounded retries/deadline.
- Sanitize the subprocess environment, inherit no secrets/open descriptors, cap
  output (proposed 4 KiB total), and bound CPU, wall time, and subprocess count.
  Kill and reap the full process group on timeout/shutdown; prevent pipe
  deadlocks, orphaned processes, and utility-created output/configuration files.
- Total job wall-time budget: at most ten seconds including DNS/cleanup. Stored
  errors are safe codes/short summaries, never raw output that may expose server
  banners, cookies, filesystem paths, environment secrets, or executable details.

Network egress restrictions at the host/container boundary are defense in depth.
An app-level allowlist is not a substitute for a firewall. No firewall, VPN,
VNet, network route, raw-socket permission, or security-group change is authorized
by this plan.

## 6. Proposed additive data model

| Table | Essential fields / constraints |
| --- | --- |
| `asset_probe_configs` | Unique asset ID FK; target, normalized target, check type, port/HTTP fields, enabled/mode/interval/timeout/threshold, config generation, `row_version`, creator/editor IDs and UTC times |
| `asset_probe_jobs` | ID, asset/config generation, immutable bounded config snapshot, manual/scheduled source, real requesting actor, due time, claim owner/expiry, `queued/running/completed/cancelled/error`, idempotency key; at most one outstanding job per asset |
| `asset_probe_runs` | Job/config generation, start/end UTC, runner label, selected IP/family, raw outcome and safe reason, latency, HTTP/TCP metadata; bounded observation history |
| `asset_probe_state` | Asset ID, last run/last success/last failure, stable outcome, current failure streak, effective config generation, next-due time and freshness basis |

Use the next ordered migration after the current ledger version, foreign keys,
checks, and indexes on due/claim state and asset/time. Do not backfill targets
from asset names/external IDs, create jobs during migration, or rewrite CVEs.

Config changes, manual job requests, enable/disable actions, and stable status
transitions enter the existing audit chain atomically with the related mutation.
Routine unchanged observations are bounded telemetry, not thousands of permanent
audit entries per day; preserve their structured run records under the stated
retention policy. Document this distinction explicitly, and never silently prune
the security audit chain. Routine scheduler/lease polls do not create audit noise.

Probe telemetry must not increment the asset inventory import revision or asset
`row_version`: a background ping must not invalidate every CSV preview/edit.
Admin-owned probe configuration is separately versioned. Current inventory
exports remain unchanged; provide explicit authorized monitoring exports with a
separate schema version, excluding command/environment secrets and pending jobs.
Importing/exporting ordinary inventory does not enable or restore monitors.

## 7. Worker coordination and F1 budgets

- Add an independent lightweight monitor loop under the existing application
  lifecycle. Do not block feed refreshes or API requests with subprocesses.
- Use SQLite-backed job claims and a shared, bounded capacity lease across both
  web workers. Network operations happen **outside** write transactions.
- Claims include owner and expiry. Commit a result only if the same owner still
  owns the claim and its asset/config generation is still enabled/current.
  Discard late results from an old target, archive, disable action, or expired
  claim; they cannot overwrite newer status.
- Cancel/terminate in-flight work on disable or configuration invalidation where
  possible; traffic already transmitted cannot be recalled. The hard job deadline
  bounds work that races with cancellation.
- Proposed defaults: 100 enabled monitors, two concurrent probes globally,
  ten job attempts/minute globally, one manual attempt/asset/minute, a queue of
  200, and a 15-minute starting interval. Apply limits to scheduled and manual work
  together, including machine callers. Validate actual cost before raising limits.
- Allow arbitrary positive requested intervals (minimum representable one second),
  not only 15/30/60-minute choices. Distinguish requested from effective cadence:
  one outstanding job/asset, coalesce missed periods, and show capacity/rate-limit
  delays. A setting cannot make checks faster than their duration or available
  capacity. Operator budgets are tunable within validated limits; never silently
  change the requested interval or claim that skipped checks ran. Coordinate
  address-level pacing/in-flight guards with Feature 1B discovery.
- A repeated manual request while work is queued/running returns that job;
  require a bounded idempotency key for reliable API retries. At capacity return
  429/503 with Retry-After, not an unbounded queue or silent drop.
- Add per-asset jitter and fair due-order selection. After sleep/restart, skip
  missed sample periods and schedule at most one catch-up observation per asset;
  never replay every missed interval. An interrupted job becomes Unknown/error,
  not a failed asset sample. Do not immediately repeat it after an uncertain send.
- Outbound network side effects cannot be exactly once across worker crashes.
  Leases/idempotency prevent duplicate active jobs normally; document the small
  possibility of a repeated probe after a crash and bound it by the same budgets.
- Retain the last 100 observations per asset, at most 10,000 overall, and at most
  seven days, whichever limit is reached first. At 15-minute intervals, 100
  observations represent about 25 hours, not seven days of guaranteed history.
  Keep compact state separately; cleanup is bounded and documented.
- Show runner heartbeat/backlog and stale results honestly. No Always On, paid
  queue, external monitoring account, billable cron, or new paid tier is added.
  F1 may prohibit ICMP and cannot reach an on-premise LAN without an existing
  route. Recommend local/private-network Docker hosting for LAN probes; do not
  provision connectivity or promise Azure can reach local devices.

## 8. API, permissions, and UI

| Proposed route | Access / behavior |
| --- | --- |
| `GET /api/assets/{id}/monitoring` | Authenticated inventory readers; config summary, capability, latest/stale state |
| `PUT /api/assets/{id}/monitoring` | Admin only; typed config plus `expected_version` (0 only for initial creation); no network contact |
| `POST /api/assets/{id}/monitoring/check` | Analyst/admin; saved enabled target only, expected config generation and idempotency key; return 202/job ID |
| `GET /api/assets/{id}/monitoring/jobs/{job_id}` | Authenticated readers; verify the job belongs to that asset |
| `GET /api/assets/{id}/monitoring/history` | Authenticated, paginated (max 100); bounded date filters |
| `GET /api/assets/{id}/monitoring/export` | Admin; bounded, versioned monitoring export |
| `GET /api/asset-monitoring/capabilities` | Authenticated; available probe types, runner perspective, safe limits; not filesystem paths or credentials |

Admin owns target/type/enablement/scheduling configuration; analysts can execute
only already approved checks. Analyst inventory CRUD cannot redirect an enabled
monitor. Machine principals follow their assigned role, rate limits and real
token attribution; no impersonated actor names. Viewers cannot trigger traffic.
Reuse cookie CSRF/trusted-origin validation and private `no-store` responses.
GET/list/page loads never enqueue probes or contact an asset.

UI changes:

- **Inventory:** Up/Down/Unknown/Stale/Disabled badge, primary method, last check
  time, and status filter; do not confuse this with inventory archive status.
- **Asset detail:** admin configuration form, target scope/capability explanation,
  authorized-traffic acknowledgement, enable/schedule controls, analyst/admin
  Check now, latest safe diagnostic, latency and bounded observation history.
- Show “from runner X,” last stable result versus latest failed check, threshold
  progress, and missing permissions separately. Explain SSH-port versus SSH-login
  checks and ICMP filtering. Use text/icons, not color alone, across all themes.
- **Priority queue:** optional availability context/filter only; no default
  filtering out Down/Unknown assets and no change to vulnerability ranking.
- Poll only a requested job with a bounded interval/maximum duration; fetch saved
  status on normal pages. No per-row network probe or permanent busy polling loop.

## 9. Implementation stages and file map

1. **Contracts and authorization:** approve destination scope and probe defaults;
   freeze state/error semantics, schemas, permission matrix, and quotas. Write
   fixtures for hostile targets and inconclusive results before adapters.
2. **Migration/read-only UI:** add config/state/job/run tables, disabled/no-data
   badges, private APIs, row versions and capability reporting. Exit: upgrades
   preserve inventory/feeds/audit; nothing initiates traffic.
3. **Secure manual slice:** implement shared target validation/pinning, fixed
   curl/ping adapters and optional nmap TCP adapter, job claims and process limits.
   Exit: configure → explicit Check now → truthful result/history works locally.
4. **State/history:** thresholds, freshness, stale-generation rejection,
   archive/disable behavior, audit transitions, quotas and monitoring export.
5. **Optional scheduling:** independent bounded loop, shared capacity/rate leases,
   fair catch-up, shutdown/recovery, and resource/backlog measurements.
6. **Review/handover:** complete role-aware UI, browser/theme/accessibility checks,
   isolated regression and container tests, operator settings, allowlist examples,
   tool installation/capability limitations, backup and rollback documentation.
   Stop for approval; do not deploy or contact real targets automatically.

Likely modules: `app/models/asset_monitoring_schemas.py`,
`app/services/asset_monitoring_service.py`, `asset_probe_service.py`,
`asset_probe_policy.py`, and `asset_monitor_worker.py`, with focused routes
registered by `app/asset_routes.py`/`app/main.py`. Extend migrations, inventory/
detail/priority templates and vanilla assets UI. Keep probe-specific transport
separate from existing outbound guards. Optional system packages are a reviewed
Docker change, not an excuse to weaken non-root or F1 settings.

## 10. Acceptance tests

- Fresh/upgrade/repeated/concurrent startup creates no targets/jobs and preserves
  existing accounts, inventory, intelligence, assessment history, and audit chain.
- Missing target/config, disabled/archived assets, illegal fields, invalid ports,
  stale config versions, and unsupported tools fail without network activity.
- Anonymous/viewer requests, analyst retargeting, cross-asset job IDs, cookie CSRF,
  origin attacks, token attribution, exports and private counts are covered.
- Shell/option injection, malicious hostnames/paths, DNS rebinding/mixed answers,
  mapped IPv6, metadata/platform/localhost destinations, redirects, environment
  proxies, curl config files, raw command flags and port-range attempts fail safe.
- Public-only RSS/webhook/provider guards remain unchanged, including their
  existing SSRF tests. An allowed LAN probe must not enable LAN webhook delivery.
- Fixture outcomes cover ICMP reply/timeout/permission failure, TCP open/refused/
  timeout, HTTP success/unexpected status/redirect/405, TLS mismatch, NXDOMAIN,
  unreachable runner, missing executable, oversized output, and hung processes.
- Test multi-address DNS, IPv4/IPv6 capability, hard DNS/job deadlines, sanitized
  stderr, bounded body/header handling, process-group cleanup and no zombie leak.
- Verify thresholds, recovery, generation reset, stale TTLs, unknown streak reset,
  and stale-clock behavior with controlled UTC/monotonic time. Availability never
  changes CVE score/state, exposure, archive state, or inventory import revision.
- Custom positive intervals are preserved, not rounded to preset choices;
  duration/capacity deferrals and coalesced missed periods remain visible. Shared
  discovery traffic cannot bypass budgets or starve monitor execution.
- With two workers, duplicate requests normally produce one active job, global
  budgets are shared, an expired owner cannot acknowledge results, and a late
  result cannot undo a newer configuration/disable/archive action.
- Sleep/restart, worker crash, queue saturation, feed refresh contention, and
  history cleanup have bounded behavior and no replay storm or fabricated uptime.
- Mock utilities/DNS by default; controlled localhost fixture listeners require
  an explicitly injected **test-only** policy. Do not add a runtime loopback
  exception or run nmap/ping/curl against the user's inventory during tests.
- Run the complete isolated suite, browser journeys, Docker non-root capability
  tests, and unchanged F1 regressions. Measure 100 monitors at a 15-minute schedule,
  worst-case timeouts, job latency, process/memory/image cost, DB growth and
  duplicate-claim behavior before enabling scheduled mode.

## 11. Rollout, recovery, and approval choices

Proposed gate: `FEATURE_ASSET_MONITORING=false`, requiring the existing asset
feature as well. Disabled means routes/navigation and **all manual/scheduled
execution** are disabled; hiding buttons alone is insufficient. Restart workers
to apply operator flag/scope changes. Validate current policy again at dispatch;
policy/config changes invalidate old queued claims/results. Keep data on disable.

Back up before migration. Use a consistent database backup for full restoration;
inventory exports are not monitor/job backups. Restore monitoring configuration
disabled and cancel old jobs, so recovering a database does not unexpectedly
restart network traffic. Keep the current F1 ephemerality warnings.

**Recommended approval defaults:** one check per asset; curl/optional-capability
ping and optional single-port nmap; no SSH authentication; manual-first rollout;
admin-owned targets; operator CIDR scope (RFC1918 when unset); 15-minute opt-in schedules;
100 enabled monitors and two shared probe slots; three failed observations to
confirm Down; no alerts or vulnerability-score changes.

**Before implementation:** confirm the deployment/runner location and authorized
target networks, and whether optional TCP/nmap support is needed in the first
slice. Exact network values belong in private deployment configuration, not in
this public planning document. No probe target or network range is authorized
merely by approving the document's architecture.

The 15-minute value above is a default only, not a minimum or fixed preset list.
Custom requested frequency is supported subject to visible resource/traffic
limits and the non-overlap/F1 constraints described above and in Feature 1B.

## 12. Implementation handover

See [operator documentation](../asset-network-operations.md) for actual settings,
tools, permissions, budgets, error/freshness semantics, selective import, restore
controls and verification commands. Standard utilities are an optional Docker
build choice, never privileged. Runtime flags default off. Following the user
request on 2026-11-02, destination scope defaults to RFC1918 when unset; explicit
overrides replace it, including empty-deny. No actual checks or schedules are
enabled by that default, and no real networks were scanned. Features 2–5 remain
unimplemented.
