# Feature 1B — Multi-network discovery and selective asset import

**Status:** proposed; planning only, not implemented or enabled.  
**Parent:** [Feature 1 — Asset-aware prioritization](01-asset-aware-prioritization.md).  
**Related:** [Feature 1A — Availability monitoring](01a-asset-availability-monitoring.md).  
**Goal:** discover responding addresses and available hostnames across explicitly authorized networks, then quickly import only the assets an administrator selects.

This extends the requested Feature 1 plan; it does not start Features 2–5.
No networks, probes, tools, schedules, or automatic imports are enabled by writing
or approving this architecture. Real target scope needs separate authorization.

## 1. Required user outcome

1. Configure a discovery profile containing **multiple networks**, exclusions,
   discovery settings, optional hostname resolution, and its own schedule.
2. Run it once or enable recurring execution at a user-selected frequency.
3. Review discovered IPs, observed hostnames, timestamps, evidence/source, and
   possible existing-inventory matches without polluting the asset inventory.
4. Select one or more specific candidates and choose **Import selected**.
5. Review default asset fields/conflicts in one short preview, then confirm an
   atomic import or explicit association with an existing asset.
6. Optionally configure an availability check afterward. Discovery/import never
   silently arms monitoring or claims that a device is vulnerable.

## 2. Discovery profiles and scope

### Per-profile settings

| Setting | Proposed behavior |
| --- | --- |
| Name / enabled | Descriptive name; disabled initially |
| Networks | Up to 16 explicit IPv4/IPv6 CIDRs per profile; show normalized boundaries and unique target count |
| Exclusions | Explicit addresses/subnets, all constrained to the approved network scope |
| Runner / network scope | This deployment's configured runner and routing context; no remote-agent provisioning |
| Discovery mode | Capability-tested, bounded nmap host discovery; optional supported ICMP mode |
| Discovery TCP ports | Small explicit list, default 80/443; up to five ports, e.g. 22/80/443; not a port range or all-port scan |
| Hostname resolution | Off/on; reverse DNS using the operator-approved resolver, with optional forward-confirmation |
| Timeout / retry / pacing | Validated per-host and per-run budgets; limited retries and concurrency |
| Schedule mode | Manual only, or recurring interval |
| Interval | Any positive whole number of seconds, with seconds/minutes/hours/days UI units; not restricted to preset choices |
| Start time | Optional first-run time; UTC storage and clear local display |
| Default imported metadata | Environment, owner/team, criticality, tags; reviewed at import, not automatically applied to inventory |

Different profiles can have independent frequencies—for example, an occasional
lab scan, hourly office discovery, and a more frequent small critical subnet.
Sample CIDRs shown in the eventual UI are examples only; do not prepopulate or
activate the user's real networks. Saving/previewing a profile does no discovery
or DNS lookup. A separate **Run now** or explicit schedule enablement starts work.

Normalize and deduplicate overlapping networks before dispatch. Compute address
cardinality **before enumeration** and apply exclusions consistently. Proposed
starting ceiling: 4,096 unique target addresses per run, including all selected
networks combined. Reject oversized profiles before allocating/enumerating them;
do not silently scan only their first addresses. A large IPv6 `/64` cannot be
exhaustively scanned; require bounded smaller ranges or explicitly known IPv6
targets. Show unsupported network families and missing capabilities clearly.

## 3. Standard discovery utility and hostname behavior

### Bounded discovery, not vulnerability scanning

- Use a dedicated, fixed nmap host-discovery adapter, separate from Feature 1A's
  one-asset/one-service adapter. Disable general port scanning, OS/service/version
  detection, scripts/NSE, traceroute, exploitation, authentication, and remote
  commands. A small TCP discovery probe list is not a list of discovered services.
- Run non-root, using an explicitly tested unprivileged connect-based discovery
  mode. Do not assume nmap's default ICMP/ARP/raw-packet behavior works in Docker
  or F1. If the required mode is unavailable, return Unsupported/Unknown rather
  than silently increasing privileges or switching to a broader scan.
- Keep nmap DNS resolution disabled. The application handles bounded hostname
  lookups separately, so discovery cannot trigger uncontrolled external queries.
- Enumerate approved numeric targets in bounded chunks and pass only those
  targets to the utility, never an unchecked network/hostname expression. Use
  fixed argument arrays, no shell, and no user-supplied flags, executable path,
  timing template, script, or input/output filename.
- Parse bounded structured output with a safe parser. Treat XML/output as
  untrusted: reject DTD/external entities, excessive nesting/size, malformed
  results, and unexpected hosts outside the dispatched chunk. Review a maintained
  safe XML parser dependency during implementation; do not ingest arbitrary
  uploaded nmap files as an unreviewed alternative input path.

Discovery detects **responses from the runner's location**. A TCP reset may
prove an address responded even though no connection was accepted; an open TCP
service check has different success semantics. No reply means **not observed by
this scan**, not powered off, absent, retired, or unimportant. Firewalls, routing,
rate limiting, ICMP restrictions, and sleeping hosts can hide real devices.

### Hostnames

- For responding addresses, optionally perform rate-limited reverse DNS with
  bounded timeouts and a resolver selected by the operator, not an arbitrary
  resolver supplied in a request. The configured DNS control channel is distinct
  from permission to probe an asset; it must not become a localhost/metadata
  exception in the HTTP/TCP probe policy.
- Store the IP even when no PTR record exists. Record hostname source, lookup
  time, canonical value, aliases, and verification outcome.
- Forward confirmation may check whether the returned hostname resolves back to
  the observed IP; record that as corroboration, **not proof of ownership or a
  stable device identity**. Do not connect to unrelated forward-lookup results.
- A PTR response alone does not demonstrate a live asset. If a future DNS-only
  inventory option is approved, label those candidates separately; the initial
  candidate list is based on discovery responses, with optional name enrichment.
- Escape all names/output. Do not infer product, operating system, CVEs,
  criticality, owner, or Internet exposure from hostnames or responsive ports.
  No mDNS/LLMNR/NetBIOS broadcast enumeration or credentialed directory queries
  are included in this first release.

## 4. Flexible scheduling: requested frequency versus effective cadence

**Do not impose a fixed 15-minute minimum or preset-only schedule.** Profiles
accept custom positive intervals, including seconds, minutes, hours, or days.
Examples: every 30 seconds, 7 minutes, 2 hours, or 3 days. Zero/negative intervals
are invalid; the smallest representable interval is one second. A conservative
default such as once daily is only an initial suggestion, not a frequency cap.

Scheduling and traffic limits are different controls:

- Store the requested interval independently of scan duration, network budgets,
  worker capacity, and observed actual start/finish times.
- Show requested cadence, next eligible run, latest actual run, running/queued
  state, duration, deferred/skipped periods, and any limiting budget.
- At most one queued/running run per profile. If the interval is shorter than the
  scan duration, **coalesce** missed occurrences into at most one pending run;
  never overlap that profile or build an unlimited backlog. A run can start again
  when the previous run finishes and global capacity/rate policy permits it.
- Track a persisted coverage cursor/cycle per profile generation. If a run is
  partial, later eligible runs rotate through previously unvisited targets instead
  of forever restarting at the first subnet. Show each network's actual coverage
  window; a partial chunk is not a complete fresh scan of all configured networks.
- Detect collisions across profiles too: the same runner/address must share
  pacing and an in-flight-target guard. Record coalesced/deferred targets rather
  than generating duplicate simultaneous traffic or fabricating observations.
- Provide a configuration-time workload estimate and warning. For example, a
  1-second interval for a large subnet may be accepted as a requested cadence,
  but cannot honestly produce a full new scan each second. Reject requests that
  cannot fit hard safety limits with a clear explanation; never silently rewrite
  their interval to 15 minutes or claim that a deferred run happened.
- Make deployment traffic/concurrency budgets operator-configurable within
  validated safety ceilings. The conservative F1 defaults are not a product-wide
  maximum frequency; an appropriately authorized, measured local deployment can
  raise them without purchasing services or weakening isolation.
- Use an independent bounded scheduler/worker loop shared across web workers,
  with second-level scheduling precision when the runner is awake. Feed refreshes
  must not block this loop. SQLite due times, claims and owner tokens prevent
  duplicate normal dispatch. Network activity occurs outside write transactions.
- Use UTC due times and monotonic time for elapsed deadlines. After restart/F1
  sleep, skip missed intervals and enqueue at most one catch-up run per profile.
  No replay storm, fake downtime, or fabricated historical samples.
- Pause, cancel, disable, and edit invalidate queued work from old profile
  generations. Stop active subprocesses where possible; already transmitted
  traffic cannot be recalled. An interrupted or partial run is labeled as such.

No interval setting can make F1 stay awake, bypass network isolation, or create
processing capacity. Frequent reliable LAN discovery should run on an existing
authorized local/private-network host. No Always On, paid scheduler, cloud
networking, firewall change, VPN, or remote scanner service is provisioned.
Calendar/cron expressions are not necessary for custom-frequency support; they
can be a separately reviewed enhancement if calendar windows are later needed.

## 5. Candidate review and quick selective import

Discovery output first enters a **staging area**, not `assets`:

- List IP, observed hostname/aliases, network/profile, first/last seen, evidence
  type, last scan result, possible inventory matches, and import/ignore state.
- Filter/search by network, IP, hostname, last-seen time, new/existing, imported,
  or ignored. Provide single-row **Import** and checkboxes with **Import selected**.
  Use 100-row pages and an explicit selection count; never interpret “select this
  page” as “silently import every matching network result.”
- Import one candidate without a multi-screen wizard; bulk-review up to 100 at
  once with shared defaults and per-row overrides. The preview/confirm boundary
  remains: no import from merely clicking a checkbox or running a scan.
- Offer a suggested stable external ID (e.g. a generated discovery identifier),
  display name from the reviewed hostname/IP, and editable environment/team/
  criticality/tags. Default exposure stays **unknown**, not assumed from network
  address or an open port. Existing asset validation and the 500-active-asset
  quota still apply; explain capacity failures before commit.
- Each row explicitly chooses **create new**, **link to selected existing asset**,
  or **skip**. An existing IP/hostname is a possible match, not permission to
  overwrite or merge. Conflicting/shared addresses or multiple matches require
  review; do not silently revive an archived asset.
- Store reviewed address/hostname observations and provenance on the imported/
  linked asset. Preserve existing names, owner/team, criticality, exposure, tags,
  software, CVE assessments and monitor targets unless an independently approved
  edit explicitly changes them. Linking adds evidence, not a hidden field merge.
- Do not arm availability checks on import. An admin can separately choose an
  imported address as a Feature 1A target, with explicit destination validation
  and enablement. Later discovery never automatically retargets that monitor.
- Ignoring a candidate suppresses routine review noise without probing it
  differently. Editing exclusions stops future contact; ignoring results alone
  does not change the configured scan scope. Show that distinction clearly.

Use purpose-bound, caller-bound, hashed, one-use preview tokens with a ten-minute
TTL. Bind to the selected immutable observations, proposed asset fields, explicit
link IDs and expected asset versions, inventory revision, scope/config generation,
and candidate import/conflict state. Revalidate permissions, quotas and conflicts
at commit. All selected asset creations/links and audit entries commit atomically
or not at all. Repeated commit/idempotency keys cannot create duplicates.

Routine rescan/last-seen telemetry must **not** invalidate every import preview.
Invalidate only material reviewed identity/conflict changes, changed inventory,
profile/scope invalidation, expired evidence, or a competing import. Proposed
default quick-import observation age: at most 24 hours; older results require a
new scan or explicit manual inventory entry rather than looking freshly verified.

## 6. Identity and history rules

- A responding **address is not necessarily one physical device**. DHCP can
  reassign it; a device can have several addresses; NAT/virtual services can share
  one. Do not create a device fingerprint from IP, PTR name or discovery port.
- Candidate keys include the runner/routing scope and canonical numeric address.
  Overlapping profiles in the same scope share candidate identity and retain all
  profile provenance. Identical private IPs in distinct routing scopes must not
  collapse into one candidate. The first release uses this deployment's existing
  scope; it does not invent or provision remote runners.
- Preserve timestamped observation snapshots on import/link, even if later DNS
  or candidate retention changes. A changed hostname becomes new evidence for
  review, not an automatic rename, inventory deletion, or cross-device merge.
- Absence in a later scan does not archive/delete assets or mark them Down.
  Discovery never writes availability state as though an equivalent configured
  Feature 1A check had run, and never changes vulnerability ranking/assessments.

## 7. Proposed additive storage and API

| Table | Essential fields / invariants |
| --- | --- |
| `asset_discovery_profiles` | Name, explicit network/exclusion lists, discovery/DNS settings, requested schedule and next due, coverage cursor/cycle, enabled, config generation, `row_version`, actor IDs/times |
| `asset_discovery_runs` | Profile generation + immutable scope/settings snapshot, request actor, due/start/end UTC, claim owner/lease, progress, counts, skipped/deferred periods, completion/partial/cancel/error reason |
| `asset_discovery_candidates` | Stable candidate ID, scope + canonical IP unique key, bounded current name metadata, first/last seen, material identity version, imported/ignored review state |
| `asset_discovery_observations` | Run/candidate/profile, observation time, response evidence, bounded DNS results/source/verification, immutable observation ID/hash |
| `asset_discovery_import_previews` | Purpose-bound token hash, actor, exact selected-observation/action payload hash, inventory/config/conflict versions, expiry and consumption |
| `asset_addresses` | Asset ID, reviewed canonical address/name, scope, source/observation time, primary/display choice; uniqueness per asset/address/scope, not a claim of globally unique device identity |
| `asset_discovery_links` | Selected candidate/observation to asset, importer/time, immutable bounded evidence snapshot; preserve provenance after transient observations expire |

Apply the next ordered migration after the installed feature migrations; no
targets/jobs/scans are backfilled or enabled. Keep monitor targets as separately
admin-approved snapshots, not live pointers that change when addresses change.
Use indexed paginated candidate/run queries and bounded cleanup. Discovery
telemetry does not increment the inventory revision; approved imports/address
edits do, in the same audited inventory transaction. Do not add discovery fields
to version-1 CSV in a way that silently triggers network execution.

| Proposed route | Permission / behavior |
| --- | --- |
| `GET/POST /api/asset-discovery/profiles` | Admin: private configuration list/create; no network contact |
| `GET/PATCH /api/asset-discovery/profiles/{id}` | Admin: typed fields and expected version; enable/schedule changes explicit |
| `POST /api/asset-discovery/profiles/{id}/runs` | Analyst/admin: approved enabled scope only, idempotent Run now, return 202 |
| `GET /api/asset-discovery/runs` and `/{run_id}` | Analyst/admin: paginated safe progress/result metadata |
| `POST /api/asset-discovery/runs/{id}/cancel` | Analyst/admin: explicit audited cancellation |
| `GET /api/asset-discovery/candidates` | Analyst/admin: private paginated review results |
| `POST /api/asset-discovery/candidates/{id}/review` | Admin: versioned ignore/unignore; no target changes |
| `POST /api/asset-discovery/import/preview` and `/commit` | Admin, matching existing bulk-import governance; selected rows only |

Viewers see imported asset data, not unreviewed network topology or discovery
controls. Analysts can run an already approved profile but cannot supply alternate
networks, resolver addresses, flags or timing overrides in that request. Admin
machine tokens follow admin rights and shared budgets; audit real token identity.
All cookie mutations use the current CSRF/origin controls; responses are private
and non-cacheable. Page loads/GETs never run scans or DNS. No public topology,
candidate counts, raw utility output, or secrets enter templates/exports.

## 8. Security and operating budgets

Extend the **dedicated probe policy**, not the existing public-only intelligence/
RSS/webhook transport. Every requested CIDR must be wholly contained in the
operator-approved scope; partial intersection does not authorize scanning the
whole CIDR. Explicitly handle network/broadcast/IPv6 semantics, exclusions,
mapped IPv6 and overlapping ranges. Hard-denied metadata, platform control,
loopback, link-local, multicast and runner-self addresses remain unscannable.
Private-network permission does not waive those denials. Discovered hostnames
do not expand the authorized target set.

Proposed initial budgets (tunable only by the operator within reviewed ceilings):

- Ten enabled profiles, 16 networks/profile, 4,096 unique target IPs/run.
- One discovery process at a time; bounded chunks (e.g. 64 IPs), up to eight
  internal connect attempts concurrently, and a default 60 target attempts/minute
  across discovery profiles. DNS has its own bounded rate/output/time allowance.
- Per-host deadline at most five seconds, per-run deadline 30 minutes; progress
  and partial results persist between chunks. Label a budget/deadline-limited
  run partial, never “network contains no other devices.” Do not reset budgets
  by creating another profile, worker, manual run, or API token.
- Estimate whether a complete pass fits those defaults before enabling a profile.
  At 60 target attempts/minute, 4,096 targets require at least about 69 minutes,
  so a 30-minute run cannot cover them all. Require explicit partial/rotating
  coverage acceptance, smaller profiles, or an operator-approved adjustment of
  pacing/deadline; never present those defaults as a full-pass guarantee.
- Coordinate address-level pacing/in-flight guards with Feature 1A monitors;
  discovery must not starve monitoring or saturate feed/API workers. Count host
  and configured-port work when estimating cost; a subprocess limit alone is not
  a network limit. Utility/kernel retries mean an attempt budget is not an exact
  packet-count guarantee.
- Bound utility output per chunk (proposed 512 KiB), validated DNS names, parser
  CPU/time and subprocess descendants. Kill/reap on timeout/cancellation; sanitize
  environment/proxies/config files and return safe errors, not raw banners.
- Retain at most 10,000 staging candidates and 50,000 transient observations,
  100 runs/profile and 1,000 overall, each with a maximum age of 30 days.
  Oldest transient data can expire under a visible retention policy; imported
  asset provenance and the permanent security audit chain remain intact.
  Short-interval schedules can reach count limits within minutes; the 30-day age
  ceiling is not a promise to retain 30 days of every scan.
  At capacity, pause/refuse new work visibly rather than consuming unbounded RAM,
  disk, permanent audit events, or subprocesses.

Audit profile/scope/schedule changes, manual run requests/cancellation, review
actions, import preview/commit and significant error/recovery transitions, not
every unchanged scheduled completion. Routine address
samples are retained telemetry, not an unbounded permanent audit stream. Commit
audited changes atomically. Make estimates and exhaustion/retention warnings
visible before enabling frequent scans. This is not an availability guarantee.

## 9. UI and delivery stages

Add a private **Discover assets** section linked from Inventory:

1. **Profiles:** multi-network editor, exclusions, safe method/capability selector,
   hostname option, custom interval/unit and first-run time, scope authorization,
   workload estimate, next due, actual cadence, enable/pause and Run now.
2. **Run view:** bounded progress, scanned/responding/unresolved/skipped counts,
   per-network summaries, partial/error reasons, cancel and saved results.
3. **Candidates:** searchable/filterable rows with IP/name/provenance, match hints,
   one-click entry into import review, bulk selection and ignore controls.
4. **Import review:** shared/per-row asset defaults, create/link/skip actions,
   conflicts/capacity, immutable observed-at evidence, explicit confirm, and links
   to newly created/existing asset pages afterward. No automatic monitoring.

Recommended implementation order:

1. Finalize scopes, scheduling/identity semantics, quotas, typed contracts and
   hostile-target fixtures; coordinate shared policy/capacity with Feature 1A.
2. Add migrations, disabled profile/candidate APIs and private read-only UI;
   existing installations must not initiate traffic after upgrade.
3. Implement one explicitly requested manual multi-network discovery slice,
   safe nmap adapter, bounded DNS enrichment, claims/progress/cancel/history.
4. Complete candidate deduplication and fast selective preview/commit import,
   asset address/provenance display, version checks and atomic auditing.
5. Add arbitrary-positive-interval scheduling, coalescing/fairness, shared budgets,
   catch-up, generation invalidation and visible effective cadence.
6. Validate UI/accessibility/themes, resource measurements, two-worker races,
   Docker non-root capabilities, rollback/restore safety and F1 constraints.
   Document settings and stop for approval before another feature or deployment.

Likely additions: discovery schemas/routes, `asset_discovery_service.py`,
`asset_discovery_worker.py`, a fixed discovery adapter and safe DNS enrichment,
shared probe-policy/capacity helpers, focused discovery templates/vanilla JS,
and isolated `scratch/` fixtures. No frontend framework, paid queue or cloud
scanner infrastructure is needed. Dependencies/packages require explicit review
during implementation, not automatic installation while planning.

## 10. Acceptance and rollout gates

- Multiple networks/exclusions/overlaps produce the correct unique bounded target
  set; unauthorized, oversized, mapped, metadata/self and enormous IPv6 targets
  are rejected/skipped before any network traffic. Partial-scope CIDRs fail safe.
- Tests cover safe fixed execution, missing/unsupported nmap modes, hostile XML,
  injected names/commands, output/deadline bounds, cancellation and child cleanup.
- Hostname lookup failures do not hide responding IPs; PTR-only data cannot be
  presented as a discovered live host, trusted identity or confirmed vulnerability.
- Arbitrary intervals such as 1 second, 30 seconds, 7 minutes, and 3 days are
  represented correctly, not rounded to 15-minute presets. Zero/negative/invalid
  values fail. Shorter-than-duration scans coalesce without overlap/backlog;
  deferred/partial/skipped timing is visible and budgets remain enforced.
- Two workers, overlapping profiles, machine callers, missed periods, profile
  edits, disable/cancel, crashes and stale lease owners cannot bypass global
  limits or overwrite a newer generation. Recovery never replays a scan storm.
- Partial runs resume/rotate coverage fairly; later networks are not permanently
  starved by restarting at the first CIDR. Coverage windows, capped retention,
  missing observations and complete-pass estimates remain truthful.
- Scan results alone create no assets. Selectively importing one or 100 candidates
  creates/links exactly those rows, preserves existing fields/evidence/states,
  enforces quotas, handles stale/conflicting/DHCP/shared-IP cases and rolls back
  everything on audit failure. Repeat commits cannot duplicate inventory.
- Routine scans do not invalidate imports or retarget monitors. Ignoring a
  candidate is distinct from excluding it. Missing results never archive an asset.
- Privacy, CSRF, roles, idempotency, export safety, retention/provenance preservation,
  migration/restore and existing outbound/F1 regressions pass in isolated suites.
- Use mocked utility/DNS results and explicitly injected test-only network
  policies; no tests run against the user's real networks. Measure small frequent
  profiles plus worst-case 4,096-target timeouts, two-worker contention, fair
  monitoring access, DB growth, process limits and effective cadence locally.

Proposed gate: `FEATURE_ASSET_DISCOVERY=false`, requiring the inventory feature
and shared probe-policy infrastructure. Discovery and availability flags are
independent: importing candidates does not enable monitoring, and disabling
discovery stops enqueueing and cancels its work without disabling inventory.
Restore profiles disabled and invalidate old jobs/preview tokens; a database
restore must not unexpectedly resume network scans. F1 data loss/sleep warnings
remain; consistent backups are still required.

**Before implementation:** approve the runner/network authorization, useful local
traffic budgets, discovery capability/ports, and hostname resolver policy.
Choose the desired schedules per profile in deployment configuration/UI. No
actual target values or resolver secrets belong in this planning document.
