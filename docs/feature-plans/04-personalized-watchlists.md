# Feature 4 — Personalized watchlists, alerts, and digests

**Status:** proposed; implement only after approval.  
**Goal:** help each analyst follow relevant intelligence without repeatedly searching or flooding shared webhook channels.  
**Prerequisites:** current feed refresh service, scheduler/leases, and safe webhook dispatcher. Feature 1/3 integrations are optional follow-ups.

## 1. Current state and gap

`refresh_service.py` sends organization-wide alerts for newly inserted critical/high CVEs and KEV entries. `webhooks` stores admin-managed destinations and coarse preferences. There are no user-owned saved criteria, read/unread notifications, matching-state history, digest jobs, or durable retry/outbox records.

The existing F1 scheduler is **best effort while the application runs**. No plan here adds billable uptime, a queue service, email service, or a separate always-on scheduler.

## 2. First-release scope

### Include

- Private watchlists owned by authenticated human users, with create/edit/pause/delete and preview.
- Initial entity type: canonical CVE intelligence combining local NVD and KEV data.
- Structured filters: exact CVE IDs, literal description terms, severity, CVSS/EPSS thresholds, and confirmed KEV membership. Conditions are ANDed across fields; values within one field are ORed.
- Clearly labeled description-term matching, **not** a claim that a vendor/product or asset is confirmed affected.
- In-app notifications with read/unread/acknowledged state, optional admin-granted webhook destinations, and immediate or daily-UTC digest mode.
- Deduplicated matching state, durable outbox claims, bounded retries, and an operator-visible failed-delivery queue.

### Exclude initially

- Arbitrary SQL/regex/code filters, email/SMS/push services, multi-tenant sharing, generic user-supplied webhook URLs, and guaranteed wall-clock delivery on F1.
- Asset-aware conditions until Feature 1 exists; published-rule events until Feature 3 exists. Actor/news subscriptions are later entity adapters, not fuzzy attribution in the first release.

## 3. Main workflow

1. A user creates criteria and previews the current matching CVEs plus any unavailable/stale source inputs.
2. The default activation behavior establishes a baseline **without alerting on all historical matches**. An explicit, bounded catch-up option can include current matches.
3. After a successful refresh, new matches or meaningful risk changes create deduplicated in-app events.
4. Optional external deliveries use only destinations an administrator has granted to that user.
5. The user reads/acknowledges notifications or receives a daily digest. Pausing stops new delivery; it does not silently erase history.
6. If the app sleeps, due digests are sent once it next runs. Show delayed/catch-up status; never advertise real-time guaranteed delivery.

Pausing cancels not-yet-sent external delivery jobs for that watchlist. Resuming establishes a fresh baseline by default; it must not unexpectedly send everything accumulated while paused. An already accepted external HTTP request cannot be recalled.

## 4. Proposed data model

| Table | Essential fields and constraints |
| --- | --- |
| `watchlists` | `id`, owner user ID, name, versioned bounded filter JSON, enabled flag, delivery mode, digest UTC time, baseline policy, generation, `row_version`, timestamps |
| `watch_matches` | Watchlist ID + canonical CVE ID, current match state, first/last seen, last notified material fingerprint, evaluation generation; unique pair |
| `watch_evaluations` | Watchlist/run ID, source state, started/completed times, counts, failure status, cursor/checkpoint |
| `notifications` | Owner, watchlist, canonical entity key, material fingerprint, bounded evidence summary, unread/read/acknowledged times; unique logical notification key |
| `notification_channel_grants` | Existing webhook ID + human user ID, granted/revoked by admin; unique pair |
| `watchlist_channels` | Watchlist + granted channel relationship; server verifies grants on creation and again at delivery |
| `notification_outbox` | Delivery/digest key, destination reference, immutable bounded payload snapshot, `pending/claimed/sent/retry/dead/cancelled`, attempts, next-attempt time, lease owner/expiry, last safe error code |
| `digest_items` | Digest ID + notification ID; unique membership so retry does not aggregate the same event repeatedly |

Personal watchlists require a canonical human `user_id`; current API-token display names are not an ownership mechanism. Account deletion removes/disables private criteria and cancels pending deliveries according to a documented retention policy, while global audit entries remain. Do not orphan work that continues sending after account deletion.

## 5. Matching, freshness, and duplicate policy

- Normalize both NVD and CISA records to the **same CVE ID**, avoiding a duplicate notification merely because both sources mention it.
- Use a typed filter schema and parameterized queries. Literal text filters escape SQL LIKE wildcards; no arbitrary expressions, templating, or unbounded regex.
- A material fingerprint includes the fields relevant to the trigger: matching state, severity, score thresholds, and confirmed KEV changes—not every description/fetch timestamp change.
- Defaults: notify on a first new match and meaningful risk changes. Do not repeatedly notify an unchanged match. Re-entry after temporary source gaps does not automatically count as a brand-new finding.
- Unknown EPSS/KEV/CVSS cannot satisfy a corresponding positive filter. Surface source availability separately rather than treating unknown as false/low risk or silently forgetting old matches.
- Failed/partial source refreshes must not clear previous membership or create a burst of “new” events when the same source recovers.
- Editing criteria increments the generation and previews/re-baselines the new selection. Historical events are not retroactively rewritten.
- Optionally evaluate against an immutable per-run snapshot/cursor so concurrent user edits cannot mix old/new filter semantics within one run.

## 6. Delivery design and F1 behavior

1. Match evaluation and logical notification/outbox insertion use short transactions and uniqueness constraints.
2. A shared worker lease claims due deliveries. Webhook HTTP happens **outside** a database write transaction.
3. Acknowledgment/retry updates require the same claim owner and current lease; another worker cannot accidentally acknowledge someone else's job.
4. Use the existing public-address-pinned outbound transport and masked destinations. Recheck account status, watch enablement, and channel authorization immediately before delivery.
5. Suggested retry schedule: approximately 1, 5, and 30 minutes with jitter; honor bounded provider `Retry-After`. Cap attempts and show dead deliveries. Do not retry permanent authorization/invalid-destination errors indefinitely.
6. A crash after the provider accepted a request but before the local acknowledgment can cause a duplicate. Promise **at-least-once delivery**, not exactly once; use provider idempotency mechanisms where actually supported.
7. Immediate delivery means “next runnable local job opportunity.” Daily digests use UTC buckets and produce at most one catch-up batch per due period, not a replay storm after sleep.
8. Bound each scheduler tick's work; preserve cursor/next-attempt state in SQLite. Do not call every intelligence provider again for each watchlist.

Existing organization-wide webhook settings remain unchanged. Warn that global broadcasts and personal watches can overlap; do not silently disable existing alerts.

## 7. Proposed API and permissions

| Route | Access / behavior |
| --- | --- |
| `GET/POST /api/watchlists` | Human owner; list/create own criteria |
| `GET/PATCH/DELETE /api/watchlists/{id}` | Owner only, with version checks; no implicit admin ownership bypass |
| `POST /api/watchlists/preview` | Human user; bounded preview, no sending |
| `POST /api/watchlists/{id}/evaluate` | Owner; rate-limited manual evaluation, respects baselines |
| `GET /api/notifications` | Human user; own events only, paginated |
| `POST /api/notifications/{id}/read` and `/acknowledge` | Owner only, idempotent |
| `GET /api/notification-channels` | Human user; only granted destination IDs/names/platforms, no secrets |
| `POST/DELETE /api/webhooks/{id}/grants/{user_id}` | Admin; audit grant changes |
| `GET /api/notification-deliveries`, `POST .../{id}/retry` | Admin; safe delivery metadata and bounded retry; no secret URLs/payload credentials |

Viewers can own in-app CVE watches because they already have intelligence read access. External sending requires explicit channel grants. Machine tokens are excluded from personal ownership in this release; a later service-subscription design can add them deliberately.

## 8. UI and implementation map

- Add `watchlist_service.py`, `notification_service.py`, `notification_dispatch_service.py`, typed schemas, and protected routes.
- Add `watchlists.html`, a small `watchlists.js`, and a notification tray/page. Display empty states, preview count, delayed-source warnings, last evaluation, and delivery history.
- Add an admin grant/dead-delivery section to Settings rather than exposing webhook secrets to users.
- Integrate post-refresh matching with `refresh_service.py` and bounded delivery/digest processing with `scheduler_service.py`. Reuse generalized leases rather than creating an independent scheduler per request.
- External payloads default to public CVE facts and a link; private asset names, case notes, and raw investigations are excluded. Do not send arbitrary user-authored templates or uncontrolled Slack/Discord mentions.

## 9. Staged implementation

1. **Private saved criteria:** ownership, schema/migrations, preview, CSRF protection, versioned edits, and no-sending baseline behavior.
2. **Match engine:** canonical CVE read model, material fingerprints, partial-refresh behavior, cursor/generation safety, and duplicate tests.
3. **In-app delivery:** notifications, read/acknowledge semantics, filter-to-source explanations, and UI. Exit: useful watchlists work without an external destination.
4. **External outbox/digests:** admin grants, claims/retries/dead queue, provider-safe payloads, UTC digest aggregation, and restart/catch-up tests.
5. **Review:** resource measurements, two-worker failure tests, UI/theme/accessibility checks, quotas, and operator documentation.

## 10. Tests and acceptance criteria

- Other users, admins without an explicit product permission, and machine tokens cannot read/change someone else's private watchlists or notifications.
- Duplicate NVD/KEV mentions, repeated refreshes, worker races, retries, and edited generations do not create duplicate logical events.
- Changes irrelevant to a filter do not re-alert; threshold crossings and newly confirmed KEV membership do.
- DNS/private-IP changes, revoked grants, deleted users, paused watches, 429 responses, timeouts, and permanent provider errors follow the specified behavior.
- A failed source refresh does not manufacture recoveries/new findings. Sleep/restart produces bounded delayed work with honest timing labels.
- The crash-after-send scenario is tested/documented as possible duplicate transport delivery, not falsely asserted exactly once.
- Proposed defaults: 20 watchlists per user, 200 total, 100 preview results, 1,000 pending external deliveries, and bounded notification retention with explicit user/admin cleanup policies. Preserve audit events when pruning notification payloads.
- No paid jobs, email service, storage, or Always On setting is introduced; F1 configuration tests remain unchanged.

## 11. Rollout, recovery, and later choices

Use `FEATURE_WATCHLISTS`, with external delivery separately disabled until grants and outbox tests pass. Disabling the feature must stop matching and sending, not merely hide the UI. Keep queued records available for review/cancellation; re-enabling must not send an unexpected backlog without confirmation.

**Recommended defaults to approve:** private CVE/KEV criteria, in-app first, historical matches suppressed on activation, public-intelligence-only webhook payloads, daily UTC digests, and admin-granted channels. Shared/team watches, asset risk triggers, actor subscriptions, and rule-publication events require explicit later adapters.
