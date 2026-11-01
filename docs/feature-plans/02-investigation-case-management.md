# Feature 2 — Investigation case management

**Status:** proposed; implement only after approval.  
**Goal:** turn a one-off IOC lookup into an owned, explainable investigation that another analyst can continue.  
**Prerequisites:** existing IOC investigator; optional links to Feature 1 assets and current detection rules.

## 1. Current state and gap

`app/services/ioc_service.py` returns a dossier and appends a short summary to `investigation_history`. That table has no actor identity, full result snapshot, case owner, notes, status, or disposition. Subsequent feed changes can change a lookup result, and the current history cannot reproduce its original evidence.

The `/investigate` workflow already requires authentication and analyst/admin access for execution. Preserve these boundaries; new case evidence is **not public**.

## 2. First-release scope

### Include

- Create a case manually or from an IOC dossier; assign it to an existing analyst/admin.
- Case statuses `open`, `in_progress`, `closed`, with reopen support and an explicit conclusion when closing.
- Conclusions `malicious`, `benign`, `security_test`, `inconclusive`; never infer a human conclusion from an automated risk score.
- Append-only analyst notes and immutable snapshots of the intelligence actually observed.
- Optional references to existing assets, CVEs, actors, and stable rule IDs; references do not imply verified attribution.
- Search/filter by reference, IOC, assignee, status, severity, and date; export a self-contained Markdown/JSON report.

### Exclude initially

- Malware/file attachments, binary uploads, remote evidence URLs fetched automatically, public sharing links, email, ticketing integrations, private per-case ACLs, and multi-tenant workspaces.
- Legal chain-of-custody guarantees, WORM storage, or a claim that a SHA-256 digest makes evidence immutable against a database administrator.

## 3. Main workflow

1. An analyst runs an IOC investigation and selects **Create case** or **Add to existing case**.
2. The server snapshots the authorized result, including capture time, provider/source state, unavailable checks, and a content hash.
3. The analyst supplies a title, severity, assignee, and initial note; an existing matching open case is suggested, not automatically merged.
4. Analysts add notes, linked context, and later snapshots as understanding evolves. Earlier evidence remains unchanged.
5. The owner closes the case with a conclusion and rationale. Reopening creates an event rather than overwriting the closure history.
6. An authorized analyst/admin exports the report; no credentials or hidden internal fields are included.

## 4. Proposed data model

| Table/change | Essential fields and constraints |
| --- | --- |
| `cases` | `id`, unique human reference such as `CD-000123`, title/summary, severity, status, nullable assignee user ID, creator actor IDs/display name, conclusion, closure reason/time, archive flag, `row_version`, timestamps |
| `case_notes` | `id`, `case_id`, plain-text body, actor identity/snapshot, optional `supersedes_note_id`, timestamp; append-only corrections rather than in-place rewriting |
| `investigation_snapshots` | `id`, normalized indicator/type, captured-by actor, capture time, schema version, canonical dossier JSON, SHA-256 digest, source freshness/availability metadata |
| `case_evidence` | `case_id`, snapshot ID, added-by actor/time; unique case/snapshot pair |
| `case_references` | `case_id`, type `asset/cve/actor/rule`, normalized target ID and display-label snapshot; unique pair |
| `case_events` | Append-only assignment, status, severity, conclusion, and archive events; link to audit event ID where appropriate |
| `investigation_history` additions | Nullable actor identifiers and snapshot ID for new entries; old entries explicitly retain unknown attribution and incomplete evidence |

- Do not rewrite old lookup summaries into fabricated full dossiers or assign them to the currently logged-in user.
- Deleted users set assignee references to null while historical actor names remain. Archived assets/rules remain intelligible through stored labels/revisions.
- A reference is not a frozen copy of another entity's content. If rule code or asset context is evidence, capture an explicit authorized snapshot; do not imply that a link to a currently mutable record reproduces its past state.
- A snapshot is application-level append-only. On read/export, recompute its digest; a mismatch is an integrity warning, not an invitation to silently recompute and overwrite it.
- Use indexes on status/updated time, assignee/status, normalized indicator, and case/event IDs. Use stable ID-based pagination, not unbounded evidence joins.

## 5. Snapshot and privacy contract

- Capture the **server's authorized result**, not arbitrary JSON supplied by the browser. When the user clicks “attach,” verify the referenced lookup belongs to an authorized principal/result.
- Record “not queried,” unknown, timeout, and failure explicitly. Preserve a source URL only if it is an existing safe reference, never a credential-bearing request URL.
- Re-investigation creates a new snapshot. The UI can compare it with an older one without rewriting the case's original evidence.
- No automatic submission of private IOCs to additional external services is introduced. Existing enrichment behavior must be explained, and local-only lookups should be an available privacy choice before using real sensitive indicators.
- Exported reports carry a classification banner and capture time. “Shareable” means an authorized user downloads a report—not an unauthenticated web link.

## 6. Proposed API and permissions

**Default:** all cases are visible to analysts/admins in this single SOC workspace. Viewers/guests cannot access case contents, counts, or exports. Assignment is workflow ownership, not an access-control boundary.

| Route | Access / behavior |
| --- | --- |
| `GET/POST /api/cases` | Analyst/admin; list/create |
| `GET/PATCH /api/cases/{id}` | Analyst/admin; validated edits with expected version |
| `POST /api/cases/{id}/transition` | Analyst/admin; close/reopen/start, with required reasons |
| `GET/POST /api/cases/{id}/notes` | Analyst/admin; append/correct notes |
| `GET/POST /api/cases/{id}/evidence` | Analyst/admin; attach authorized snapshot, deduplicate |
| `POST /api/cases/{id}/references` | Analyst/admin; validate referenced entity access/existence |
| `POST /api/cases/{id}/archive` | Admin; retain content and audit trail |
| `GET /api/cases/{id}/export?format=json\|markdown` | Analyst/admin; bounded report export, audit event |
| `POST /api/investigations` | Analyst/admin; canonical execute-and-capture operation returning dossier plus snapshot/history IDs |
| `GET /api/investigations/{snapshot_id}` | Analyst/admin; retrieve a captured result without re-running enrichment or writing duplicate history |

Human actors can be assigned; machine tokens may create/append if their role permits, but are identified as service actors and cannot impersonate the assignee. Browser-cookie mutations need CSRF protection.

### Existing investigation compatibility

Move the new UI to explicit POST execution and GET result-by-ID rendering. Make GET pages safe to reload without creating duplicate evidence. Keep the old `/api/investigate` response contract during a documented transition; deprecate its implicit history mutation and cover the chosen compatibility behavior in regression tests. Do not silently change all existing history into cases.

## 7. UI and implementation map

- Add `case_service.py`, `investigation_snapshot_service.py`, case schemas, and protected case/investigation routes.
- Add `cases.html`, `case_detail.html`, and `cases.js`; integrate **Create/attach case** into `investigate.html`.
- Case detail: summary/owner, evidence list, chronology, source/unknown warnings, notes, linked context, and close/reopen controls.
- Provide links to **existing** rule/asset details; do not copy editable foreign records into a case and call them authoritative.
- Escape all notes/titles. First release stores plain text and builds Markdown reports safely; HTML rendering of user Markdown is unnecessary.

## 8. Staged implementation

1. **Contracts/migration:** case permissions, snapshot schema, additive tables/indexes, legacy-history treatment, transitions, and canonical actor IDs.
2. **Capture:** server-side dossier snapshots and integrity checks; POST execution/result retrieval; explicit local-only privacy behavior. Exit: a refresh cannot alter previous evidence.
3. **Case operations:** create/assign/edit/transition, append-only notes, references, audit events, and stale-edit handling. Exit: deleted-assignee and reopen cases behave predictably.
4. **Reports:** versioned JSON and Markdown export, classification/redaction rules, pagination/size guards, and export audit records.
5. **UI/review:** complete investigation → case → note → close → export flow; browser/theme/accessibility checks and recovery documentation.

## 9. Tests and acceptance criteria

- Anonymous/viewer requests cannot obtain case data through detail, list, counters, search, reference resolution, or exports.
- Every case mutation is attributed to the real human/token principal and audited atomically.
- A stale update returns 409; concurrent evidence attachments create one relationship, not duplicates.
- A source timeout is preserved as unavailable evidence; EICAR remains a test file, and unknown IOCs do not become malicious merely because a case exists.
- Snapshot edits/deletion attempts are rejected by the application; direct tampering is detected on read/export.
- Closing requires a conclusion and rationale; reopening preserves the previous closure event.
- Removing an assignee account does not erase notes, cases, or snapshots. Legacy history remains distinguishable from fully captured evidence.
- Proposed F1 limits: 200 cases, 25 snapshots per case, 256 KiB per snapshot, 8,000 characters per note, and 50 MiB aggregate snapshot storage. Reject over-limit writes visibly; do not silently truncate evidence.
- Large exports are bounded/streamed; malicious text remains inert in the browser and exported metadata never includes tokens, MFA secrets, or passwords.

## 10. Rollout, recovery, and later choices

Use `FEATURE_CASE_MANAGEMENT`; existing one-off investigations remain available when disabled. Require a backup before migration and document that F1 database replacement loses unsaved cases. Exports can support manual reporting but are not a complete database restore mechanism.

**Recommended defaults to approve:** analyst/admin team visibility, immutable text/JSON evidence, plain-text append-only notes, no attachments, and no public links. A later private-case model needs explicit ACL design across search, counts, exports, and background notifications before it can be offered safely.
