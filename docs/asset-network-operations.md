# Asset availability and network discovery

Feature 1A adds per-asset availability checks; Feature 1B adds multi-network
discovery and selective import. Both are implemented, **disabled by default**,
and independent of vulnerability scoring. No deployment, VPN, firewall rule,
paid scheduler, or Always On change is included.

## Enable configuration and authorize traffic separately

Keep the existing signing key/database settings and enable the desired UI/API:

```bash
export FEATURE_ASSET_PRIORITIZATION=true
export FEATURE_ASSET_MONITORING=true
export FEATURE_ASSET_DISCOVERY=true
# Match the actual browser-facing origin:
export PUBLIC_BASE_URL=http://127.0.0.1:8765
```

Restart **all** workers after changing environment settings. Editing
`.env.example` does not load settings. Existing processes do not pick up exports
from another terminal. A reload watcher also does not reload its parent's
environment; restart the launcher when changing these settings.

When `ASSET_PROBE_ALLOWED_CIDRS` is **unset**, the permitted destination scope
defaults to the three RFC1918 IPv4 ranges: `10.0.0.0/8`, `172.16.0.0/12`, and
`192.168.0.0/16`. Public IPs and IPv6 ULA are not permitted by default. This
default does not create targets, enable configurations, or start scans; admins
must still explicitly configure and authorize each check/profile.

An explicit comma-separated CIDR list **replaces**, rather than adds to, those
defaults. Set a narrower scope if needed, or explicitly include other authorized
IPv4/IPv6 networks. An explicitly **empty** value (`ASSET_PROBE_ALLOWED_CIDRS=''`)
blocks all target traffic, even RFC1918. To use the default on an installation
previously configured with an empty value, remove that override from its startup
configuration and fully restart all workers. Merely exporting variables in
another terminal does not change an existing launcher's configuration.

Admins can prepare disabled drafts even with an empty allowlist. Only scan
networks you own or have permission to test. No real networks were scanned
during implementation or the RFC1918-default update.

Additional operator settings:

| Variable | Default / range |
| --- | --- |
| `ASSET_PROBE_ALLOWED_CIDRS` | Unset: RFC1918 ranges above; explicit list replaces defaults; empty denies all; no universal `/0` |
| `ASSET_PROBE_SCOPE_LABEL` | `local`; stable deployment/routing identity, max 80 characters |
| `ASSET_PROBE_RATE_PER_MINUTE` | 10; configurable 1–600 monitoring attempts/minute |
| `ASSET_DISCOVERY_RATE_PER_MINUTE` | 60; configurable 1–600 discovery port-attempt units/minute |
| `ASSET_PROBE_DNS_RATE_PER_MINUTE` | 60; configurable 1–600 logical resolver operations/minute |

Pacing is shared across workers/callers in fixed UTC minute windows. A discovered
target using two configured discovery ports costs two units. Forward-confirmed
PTR enrichment conservatively reserves up to nine resolver operations. DNS/OS/
utility retransmits can produce multiple packets; these are not exact packet
count limits. Limits, queue depth, heartbeat and utility availability are shown
in the configuration pages' capability information.

The allowlist is **not editable through the browser**. RFC1918 defaults and admin approval of a target
cannot override hard denials for runner-self, loopback, link-local, multicast,
metadata/platform control addresses, or other prohibited special-use addresses.
IPv4-mapped IPv6 is normalized. CIDRs must be wholly within an approved range;
partial overlap is insufficient. DNS answers are revalidated and pinned before
contact; mixed permitted/prohibited answers reject the check. Dual-stack names
may need both returned address ranges authorized.

LAN checks require an existing route from the app's network namespace. A Docker
container/F1 instance cannot automatically reach your office LAN, and F1 can
sleep or deny ICMP. Use an existing authorized local/private-network host for
frequent LAN work. Do not grant root, privileged-container access, or raw-socket
capabilities just to make ping work.

## Standard tools

- HTTP/HTTPS: `curl`, pinned address, verified TLS, HEAD/optional GET health path.
- ICMP: `iputils` `ping`; unavailable/permission errors are Unknown, not Down.
- TCP service: unprivileged single-port `nmap` connect check; port 22 means
  **SSH port reachable**, not SSH login verified.
- Discovery: bounded unprivileged nmap host discovery using up to five TCP
  discovery ports. No OS/service/version scanning, scripts/NSE, authentication,
  broad port scan, or arbitrary commands are available.

For local Python operation, the operator installs the desired standard packages
at their normal `/usr/bin` or `/bin` paths. Missing tools do not break startup;
capability checks report them and requested work returns an Unknown/error code.
The default Docker image does not add these optional packages. Build a tools
image explicitly when needed:

```bash
docker build --build-arg INSTALL_ASSET_NETWORK_TOOLS=true -t cyberdash:asset-network .
```

This installs Debian curl/iputils-ping/nmap and removes ping's setuid/setgid/file
capability privileges. Datagram ICMP still depends on the host kernel policy.
The container remains non-root. Review the standard tools' licenses, especially
nmap's distribution terms, before distributing a customized image. Package
versions/security fixes follow the selected Debian repository, not a promise of
identical versions on every future build.

## Per-asset availability

Open an asset detail page. Admins can set one target and primary method, timeout
(1–5 seconds), HTTP method/relative path/expected response codes, and the number
of failures to confirm Down (default three). A future/current DNS name is user-
provided context, not a verified device identity. No credentials, arbitrary
headers, insecure-TLS option, query strings, or complete arbitrary URLs are
accepted. GET health endpoints must be explicitly approved as non-mutating.
Redirects are not followed. Response content is bounded and discarded; only safe
result metadata is retained, not bodies, headers, banners or raw tool output.

Saving is metadata-only. An enabled manual-only configuration runs only after
**Check now**. Scheduling is opt-in; its first automatic run waits one interval.
Analysts/admins can request an approved enabled check; viewers can read saved
state/history. Admins own targets/settings and can export the latest 100 jobs.

Display states:

- **Up:** this configured check recently succeeded from this runner.
- **Down:** consecutive completed negative observations reached the threshold;
  not proof that a device is powered off.
- **Unknown:** no measurement, an unconfirmed initial failure, missing tools,
  permissions, DNS/policy/runner failure, or interrupted work.
- **Stale:** the latest valid measurement exceeded two scheduled intervals plus
  ten seconds, or 15 minutes in manual mode. Old success is not fresh availability.
- **Disabled:** not enabled, including archived assets.

Queued/running overlays do not create measurements. Latest raw outcome, reason,
failure progress and last success remain visible separately. Unknown resets the
failure streak. A later successful observation recovers to Up. Archive disables
the monitor; restore does not resume traffic until an admin re-enables it.

Inventory/priority pages can display/filter availability. **Default priority
results and scores are unchanged**: Down/Unknown does not remediate a CVE, reduce
criticality/exposure, or hide the asset. Background telemetry does not bump the
inventory revision or invalidate every CSV preview/edit.

## Multi-network discovery and schedules

From Inventory choose **Discover assets**. Admins configure profiles with up to
16 canonical networks, exclusions, up to five individual TCP discovery ports,
timeouts, and optional PTR/forward-confirmation using the host's configured
resolver. Review that resolver's routing/NSS policy before authorizing DNS use;
the UI cannot select arbitrary resolver destinations. No separate application
multicast/broadcast enumeration or directory integration is performed.

The raw combined address-space ceiling is 4,096 before enumeration, even when
large exclusions would later shrink it. Overlaps are deduplicated; prohibited/
self/network/broadcast addresses are excluded as applicable. Exhaustive IPv6
`/64` enumeration is not supported. Save/preview does not resolve names or scan.

Enable manual mode and use **Run now**, or explicitly enable scheduling:

- Custom positive whole-second intervals, from one second through one year,
  with seconds/minutes/hours/days units. Defaults (15 minutes for monitoring,
  one day for discovery) are suggestions, not a fixed minimum or preset-only UI.
- Requested frequency is distinct from sustainable cadence. One outstanding job
  per asset/profile; missed periods coalesce instead of overlapping/backlogging.
- Two shared active jobs; at most one discovery process with up to eight target
  connect attempts per chunk. Address locks prevent simultaneous monitor and
  discovery contact to the same IP within this deployment.
- A scan has a 30-minute run budget. A 4,096-target/two-port pass at 60 units/minute
  takes at least about 137 minutes: split the scope, change approved operator
  budgets, or explicitly accept rotating partial coverage. Do not assume a large
  network can be scanned completely every second.
- A persisted cursor rotates partial runs through later targets. Per-network
  counts and actual coverage times appear in run details. No response means
  not observed, not absent or Down. Discovery does not write monitoring state.
- F1 sleep/restarts skip missed periods, with at most one catch-up job per
  profile. An interrupted process is Unknown/error; external probe execution
  cannot be guaranteed exactly once across crashes.

Run now returns a queued job ID. Progress, saved results, cancellation and
budget/target-busy deferrals are visible. The browser polls only a requested job
for up to a minute, then offers manual saved-status refresh; page loads/GETs
never start probes. A full queue returns 503/Retry-After, excessive manual requests
429; one manual request per asset/profile/minute is allowed and existing pending
work is reused. Idempotency applies while the corresponding job is retained.

## Selective import, address identity and evidence

Discovery creates staged candidates, **not assets**. Filter by IP/name, network,
profile or review state. Select up to 100 specific candidates or one row's
**Import…** action. Review shared/per-row defaults and choose create, explicitly
link to an existing asset ID/version, or skip. Then validate the exact preview
and explicitly confirm. The current 500-active-asset quota remains in force.

Import tokens are purpose/caller-bound, hashed, one-use and valid for ten minutes.
Selected observations must be at most 24 hours old. Inventory/version/identity/
review/source-policy changes invalidate previews; ordinary last-seen updates do
not. Failed validation, conflicts, quotas or audit writes roll back the whole
selected batch. No automatic whole-network or schedule-based import is provided.

An IP/PTR name can be shared/reassigned and is not a stable device fingerprint.
Possible matches are hints, not automatic merges. Existing asset fields, software,
CVE evidence/states and monitor targets are preserved. Exposure defaults to
unknown. Importing addresses **never enables monitoring** or changes rankings.

Imported assets retain latest reviewed address observations plus append-only
reviewed evidence snapshots, readable on their detail page. A changed observed
name reopens candidate binding review, not the asset itself; original inventory
names and monitor targets are untouched. Admins can explicitly **Review binding**
to reconsider a shared/reassigned IP even when its name stayed the same. A later
reviewed link keeps earlier snapshots, rather than silently erasing provenance.

Ignoring review noise does not exclude an address from future scans. Edit profile
exclusions to stop contact. Missing/changed discovery results do not archive or
delete assets. Profiles/candidate review are admin-controlled; analysts can run
approved profiles and view discovery results. Viewers see imported inventory and
monitoring data, not unreviewed discovery topology. Cookie writes use the existing
CSRF/origin checks; machine tokens retain their real role/token attribution.

## Retention, backup and restore

Initial limits: 100 enabled monitors, ten enabled/50 retained profiles, 200 pending
jobs, 100 retained jobs per scope, 10,000 monitor jobs overall (max seven days),
1,000 discovery runs overall (max 30 days), 10,000 candidates and 50,000 transient
observations (max 30 days). The earliest count/age limit wins; frequent schedules
can exhaust history counts within minutes. Retained reviewed address/evidence
records are separately capped at 20,000 each and are not pruned as telemetry.
Candidate exhaustion stops work visibly; imported snapshots survive transient
candidate/run/observation cleanup. The permanent security audit chain is not pruned.

The additive version-2 migration creates empty network tables and preserves
existing data. Back up before upgrading. Feature disable stops execution and
hides its controls/routes without dropping tables; pending stale claims cannot
overwrite newer configuration. Scope/flag environment changes require restart.

Before restoring a database, stop the app and disable the network feature flags.
After restore/upgrade, use the configured signing key/database environment to run:

```bash
python -m scripts.pause_asset_network --confirm
```

This operator-only command pauses all persisted monitor/discovery configurations,
cancels outstanding jobs, invalidates discovery import tokens and records an
atomic audit event, without deleting inventory/history or contacting targets.
Review scope/configuration before re-enabling. It is **not automatic detection
of a restore**: restoring a live enabled database and skipping this step can
resume its schedules. Do not use destructive schema downgrades. Ordinary inventory
exports are not full backups of address evidence, identities or scheduled work.

## Verification and known limits

```bash
python -m scratch.run_tests
python -m scratch.benchmark_asset_network
docker build --build-arg INSTALL_ASSET_NETWORK_TOOLS=true -t cyberdash:asset-network .
python -m scratch.container_smoke cyberdash:asset-network --network
python -m scratch.container_probe_fixture cyberdash:asset-network
```

The suites use isolated databases and mocked probes/DNS, including unset/default,
explicit replacement, empty-deny and hard-denial checks. The last command exercises
real adapters only against a disposable container's own loopback HTTP/TCP fixture,
with `--network none`; it does not add a production self-address exception or scan
the user's networks. `python -m scratch.preview_asset_network` starts a separate
mock UI at `http://localhost:8766`; use that hostname to keep its test cookies
separate from a live instance on `127.0.0.1`. All its probe/DNS results are clearly simulated.

No new Python dependency was required. Fixed utility flags, resource-limited
subprocesses, safe bounded XML parsing, validated/pinned destinations, non-root
operation and shared budgets are defense in depth, not an enterprise monitoring
or uptime guarantee. Confirm actual route/ICMP/tool capabilities on authorized
targets before relying on results. Azure F1 remains best-effort and ephemeral;
no cloud resources were deployed and Features 2–5 are unchanged.
