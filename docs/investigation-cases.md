# Investigation case management (Feature 2)

Case management is implemented behind `FEATURE_CASE_MANAGEMENT`, default `false`.
It uses existing FastAPI/SQLite/Jinja/vanilla JavaScript infrastructure. No new
Python dependencies, cloud resources, paid services, file attachments, email or
public report links are introduced. Features 3–5 remain outside this release.

## Enable and recover

Back up the configured database before upgrade. Preserve its signing key and
accounts, set `FEATURE_CASE_MANAGEMENT=true` in the actual startup environment,
and restart **all** web workers. A reloader does not reload its parent's environment.
The additive version-3 migration creates empty case/snapshot tables and adds
nullable attribution/snapshot columns to lookup history; it does not create cases
from old records, invent historical evidence, or contact providers.

Case management does not require the asset feature flag. Asset references are
available only when inventory is enabled; other case operations remain independent.
Disabling case management hides its routes/UI without deleting its tables. Never
perform a destructive down-migration. A verified full database backup, with the
matching signing key, is the recovery mechanism; report exports are not database
restore packages. F1 can sleep and replacement can lose SQLite data. Back up off
the instance; local Docker testing can use an existing local volume.

## Permissions and ownership

- All cases, notes, evidence and reports are team-visible to analysts/admins.
  Assignment is workflow ownership, **not** a private-case ACL.
- Viewers/guests cannot access case pages, list/search results, assignee lists,
  evidence, counts, reports or captured investigation results.
- Analysts/admins create/edit/assign cases, add notes/references/evidence, and
  reopen/start cases. Only the assigned human analyst or an admin can close one.
  Reassignment is allowed as a team workflow operation and is recorded.
- Assignment accepts existing human analyst/admin IDs, not tokens or viewers.
  Unassigned cases are supported. Human API creates default to the caller when
  assignee is omitted; the UI explicitly offers unassigned or a selected owner.
- Role-permitted machine tokens create/append as service actors with their actual
  token ID; they cannot impersonate a human assignee. An admin token can perform
  admin operations. Existing token revocation/rate limits are unchanged.
- Only admins archive/restore cases. Archiving retains all content and consumes
  the same storage quota. Closed/archived cases are read-only until reopened/restored.
- Deleting an account nulls its assignment and actor foreign keys, retaining actor
  display-name snapshots and evidence. Captured payloads retain identity as it was
  recorded; a deleted account is not assigned to another person automatically.

Cookie mutations require session-bound CSRF and same-origin checks. Explicit API
credentials use existing role checks; invalid supplied credentials never fall
back to a browser cookie. Responses are private/no-store, including errors and
downloads. User text is plain text, not HTML or executable Markdown.

## Investigation → case workflow

1. Open **IOC investigator** as an analyst/admin. Enter an IP, domain, HTTP(S) URL,
   or MD5/SHA1/SHA256 hash.
2. Leave **Local-only** checked for sensitive indicators. This uses only cached
   local threat indicators and the local hash catalog: no DNS or HTTP requests.
3. Click **Investigate and preserve result**. The server executes the lookup and
   atomically stores a canonical versioned snapshot, SHA-256 digest, capture time,
   source availability/freshness, actor IDs, history summary and audit event.
4. Review the verdict, mode and source states. EICAR remains a benign test; an
   unknown IOC stays unknown. Creating a case never changes the automated verdict.
5. Create a case from this result or explicitly attach it to an existing case ID.
   Matching open cases are suggestions, never automatically merged. Manual case
   creation without IOC evidence is also supported under **Cases**.
6. Assign an owner/severity, append notes and references. Correct a note by adding
   another note with **Corrects note ID**; originals are not edited/deleted.
7. Close with an explicit human conclusion (`malicious`, `benign`, `security_test`,
   `inconclusive`) and rationale. Reopening requires a reason; earlier closure
   information remains in the chronology.
8. Download the versioned JSON or Markdown report. Both include the classification
   banner, captured evidence, notes, references and event history.

Every case update checks `expected_version`; stale writes return **409**, not
last-writer-wins. Adding notes/references/new evidence also advances this version.
Concurrent attachment of the same evidence deduplicates the relationship.
No page load, saved-result GET, comparison, or case export reruns enrichment.

## Privacy, source status and integrity

Unchecking local-only explicitly permits the **existing** enrichment behavior:
DNS queries use the host's resolver, and public-IP geolocation sends the IP to
`ip-api.com` over HTTP. DNS names/IPs can therefore leave the app. No submitted
URL is fetched, no new reputation provider receives an IOC automatically, and
VirusTotal/OTX/other pivots are links, **not evidence of a provider query**.
Private IP geolocation is not queried. Use local-only for sensitive indicators.

`not_queried`, `available`, `unavailable` and geolocation `timeout` states are
preserved where observed. Stored feed state describes the local cache at capture
time, not a fresh external query. No recent feed-state row means freshness is
unknown. There is no verified actor attribution from free-text similarity.

The browser submits only the indicator and privacy choice, not an arbitrary
result dossier. Unattached captures are readable/attachable only by their capture
principal. Attaching them shares them with the analyst/admin team, including
archived cases. Knowing another user's unshared snapshot ID is insufficient.
Shared snapshots may be attached to another case by authorized teammates.

Re-investigation creates a new immutable snapshot. Saved results are addressed by
ID so refresh/back cannot accidentally regenerate history. **Compare two saved
snapshots** shows dossier fields that changed, without modifying either one.
Different privacy modes/source availability can explain a difference.

Digests are recomputed on read/export. Mismatches are shown as **INTEGRITY WARNING**
and remain flagged in reports; they cannot be attached as new valid evidence.
There are no snapshot-edit/delete endpoints. These are application-level controls,
not WORM storage or legal chain-of-custody guarantees: someone able to rewrite both
the database evidence and digest can bypass this check. Keep independent backups
and audit checkpoints for stronger detection.

Credential-bearing URLs, sensitive query parameters and fragments are rejected
for new captures. Structured credential fields/unsafe source URLs are omitted
from captured provider metadata; authentication tokens, signing keys and password
hashes are never copied from request context. **Do not paste credentials into
notes, titles, indicators or other free text**: arbitrary pasted secrets cannot
be reliably recognized/redacted. Reports contain the user-entered case text.

## Context references and reports

Link existing assets, CVEs, threat actors and stable rule IDs. Stored labels keep
deleted/archived context intelligible; references do not imply verified attribution,
confirmed vulnerability, or frozen rule code. A current-details link can change
and is never represented as a captured revision. No automatic entity merge,
inventory/priority change, rule publication or notification is triggered.

JSON reports are self-contained schema version 1. Markdown reports provide a
case summary/notes/evidence overview plus complete structured content. User text
is encoded as inert indented code (HTML-escaped), not rendered as arbitrary HTML,
links, images or Markdown. Downloads use controlled filenames and are audited.
There are no public URLs, automatic shares or export-import/restore endpoints.

## Limits and errors

| Limit | Initial value |
| --- | --- |
| Cases, including archived | 200 |
| Snapshots per case | 25 |
| Captured snapshots overall, including unattached | 1,000 |
| Snapshot payload | 256 KiB |
| Aggregate snapshot payload storage | 50 MiB |
| Notes per case | 200, each at most 8,000 characters |
| Context references per case | 100 |
| Events per case | 1,000 |
| JSON mutation request body | 64 KiB |
| Report download | 12 MiB |

The earliest limit wins. Quotas include unattached snapshots; snapshots are not
automatically deleted. Ordinary lookup history can be cleared by an admin, but
doing so does **not** remove snapshots or attached case evidence or reclaim its
quota. Review storage/backup policy before collecting high-volume evidence.
Oversize captures/reports return **413** without silent truncation. Quota,
linked-record and stale-version conflicts return **409**. Invalid fields return
**422**, missing/inaccessible unshared captures **404**, guests **401** and
forbidden roles **403**. Case search/results and child collections use bounded
ID-keyset pagination; filters include IOC, reference, owner, status, severity and
UTC creation dates. Counts of whole evidence joins are not computed on each page.

## Existing-client compatibility

When case management is enabled, the UI uses `POST /api/investigations` and
`GET /api/investigations/{id}`. Legacy `GET /api/investigate?ioc=…` retains its
dossier response shape and existing enrichment behavior but **does not write
history or preserve evidence**; it returns `Deprecation: true` and a successor
link. Move evidence-producing clients to explicit POST capture. Case management
disabled retains the old one-off workflow/history behavior. `/investigate?ioc=…`
on the new UI prefills a draft only; users must explicitly execute it.

`/api/investigate/history` remains a bounded summary API; with case management
enabled it is restricted to analysts/admins. Null actor/snapshot IDs in legacy
rows mean unknown attribution and uncaptured evidence, not the current user.
They are not retroactively promoted into cases. Recent history shows that
distinction in the new UI. Admin history clearing requires CSRF for cookie calls.

## Verification

```bash
python -B -m scratch.run_tests
python -B -m scratch.benchmark_cases
docker build -t cyberdash:cases .
python -B -m scratch.container_smoke cyberdash:cases --cases
python -B -m scratch.preview_cases
```

Tests use isolated databases and block or mock enrichment. The preview runs at
`http://localhost:8767`, uses synthetic local-only evidence and forbids all network
enrichment; its test cookies are separate from the live `127.0.0.1` instance.
The benchmark uses synthetic fixtures at the case/snapshot/count limits and
reports measurements rather than a scalability, F1 latency or uptime promise.
See the [validation handover](investigation-cases-validation.md) for observed
results and the local rollout boundary.
