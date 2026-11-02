"""Team-visible case workflow, append-only history and bounded safe reports."""
import html
import json
import re
from fastapi import HTTPException
from app import config
from app.database import get_connection
from app.services.case_common import actor_values, audit, canonical, check_version, literal_like, now, write_transaction
from app.services.investigation_snapshot_service import authorized_snapshot, normalize, snapshot_record

LIMITS = {'cases': 200, 'evidence_per_case': 25, 'notes_per_case': 200, 'references_per_case': 100,
          'events_per_case': 1000, 'note_characters': 8000, 'snapshot_bytes': 262144,
          'snapshot_storage_bytes': 50*1024*1024, 'snapshots': 1000, 'export_bytes': 12*1024*1024}
CASE_SELECT = '''SELECT c.*,u.username AS assignee_name FROM cases c LEFT JOIN users u ON u.id=c.assignee_user_id'''


def record(conn, case_id, *, writable=False):
    row = conn.execute(CASE_SELECT + ' WHERE c.id=?', (case_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'Case not found.')
    if writable and (row['is_archived'] or row['status'] == 'closed'):
        raise HTTPException(409, 'Restore/reopen the case before editing or adding evidence.')
    return dict(row)


def get_case(case_id):
    with get_connection() as conn:
        return record(conn, case_id)


def assignees():
    with get_connection() as conn:
        return {'items': [dict(r) for r in conn.execute("SELECT id,username,role FROM users WHERE role IN ('analyst','admin') ORDER BY username LIMIT 1000")]}


def validate_assignee(conn, user_id):
    if user_id is not None and not conn.execute("SELECT 1 FROM users WHERE id=? AND role IN ('analyst','admin')", (user_id,)).fetchone():
        raise HTTPException(422, 'Assign cases only to an existing human analyst/admin.')


def event(conn, case_id, actor, kind, payload):
    if conn.execute('SELECT COUNT(*) FROM case_events WHERE case_id=?', (case_id,)).fetchone()[0] >= LIMITS['events_per_case']:
        raise HTTPException(409, 'Case event limit reached; existing history has not been truncated.')
    audit_id = audit(conn, actor, 'CASE_' + kind.upper(), case_id)
    conn.execute('''INSERT INTO case_events(case_id,kind,actor_user_id,actor_token_id,actor_name,payload_json,audit_event_id,created_at)
        VALUES (?,?,?,?,?,?,?,?)''', (case_id, kind, *actor_values(actor), canonical(payload), audit_id, now()))


def bump(conn, case_id):
    conn.execute('UPDATE cases SET row_version=row_version+1,updated_at=? WHERE id=?', (now(), case_id))


def list_cases(*, search='', indicator='', status='', severity='', assignee_user_id=None, archived=False,
               created_from='', created_to='', before_id=None, limit=50, active_only=False, reference_kind='', target_id=''):
    clauses, args = ['c.is_archived=?'], [int(archived)]
    if search:
        clauses.append("(c.reference LIKE ? ESCAPE '\\' OR c.title LIKE ? ESCAPE '\\' OR c.summary LIKE ? ESCAPE '\\')")
        args.extend([literal_like(search)]*3)
    if indicator:
        indicator, _ = normalize(indicator)
        clauses.append('EXISTS(SELECT 1 FROM case_evidence e JOIN investigation_snapshots s ON s.id=e.snapshot_id WHERE e.case_id=c.id AND s.indicator=?)')
        args.append(indicator)
    for column, value in (('status', status), ('severity', severity), ('assignee_user_id', assignee_user_id)):
        if value is not None and value != '':
            clauses.append(f'c.{column}=?'); args.append(value)
    if active_only:
        clauses.append("c.status!='closed'")
    if reference_kind:
        clauses.append('EXISTS(SELECT 1 FROM case_references r WHERE r.case_id=c.id AND r.kind=? AND r.target_id=?)')
        args.extend([reference_kind, target_id.upper() if reference_kind == 'cve' else target_id])
    if created_from:
        clauses.append('c.created_at>=?'); args.append(created_from)
    if created_to:
        clauses.append('c.created_at<?'); args.append(created_to)
    if before_id:
        clauses.append('c.id<?'); args.append(before_id)
    with get_connection() as conn:
        rows = conn.execute(CASE_SELECT + ' WHERE ' + ' AND '.join(clauses) + ' ORDER BY c.id DESC LIMIT ?', (*args, limit+1)).fetchall()
    return {'items': [dict(r) for r in rows[:limit]], 'next_before_id': rows[limit-1]['id'] if len(rows)>limit else None, 'limits': LIMITS}


def _attach(conn, case_id, snapshot_id, actor):
    authorized_snapshot(conn, snapshot_id, actor, require_integrity=True)
    if conn.execute('SELECT 1 FROM case_evidence WHERE case_id=? AND snapshot_id=?', (case_id, snapshot_id)).fetchone():
        return False
    if conn.execute('SELECT COUNT(*) FROM case_evidence WHERE case_id=?', (case_id,)).fetchone()[0] >= LIMITS['evidence_per_case']:
        raise HTTPException(409, 'At most 25 evidence snapshots per case.')
    conn.execute('INSERT INTO case_evidence(case_id,snapshot_id,actor_user_id,actor_token_id,actor_name,created_at) VALUES (?,?,?,?,?,?)',
                 (case_id, snapshot_id, *actor_values(actor), now()))
    event(conn, case_id, actor, 'evidence_attached', {'snapshot_id': snapshot_id})
    return True


def create(model, actor):
    with write_transaction() as conn:
        if conn.execute('SELECT COUNT(*) FROM cases').fetchone()[0] >= LIMITS['cases']:
            raise HTTPException(409, 'At most 200 retained cases, including archived cases.')
        assignee = model.assignee_user_id
        if 'assignee_user_id' not in model.model_fields_set and not actor.get('is_api_token'):
            assignee = actor.get('user_id')
        validate_assignee(conn, assignee)
        timestamp = now()
        case_id = conn.execute('''INSERT INTO cases(title,summary,severity,assignee_user_id,actor_user_id,actor_token_id,actor_name,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)''', (model.title, model.summary, model.severity, assignee, *actor_values(actor), timestamp, timestamp)).lastrowid
        conn.execute('UPDATE cases SET reference=? WHERE id=?', (f'CD-{case_id:06d}', case_id))
        event(conn, case_id, actor, 'created', {'title': model.title, 'severity': model.severity, 'assignee_user_id': assignee})
        if model.initial_note:
            conn.execute('INSERT INTO case_notes(case_id,body,actor_user_id,actor_token_id,actor_name,created_at) VALUES (?,?,?,?,?,?)',
                         (case_id, model.initial_note, *actor_values(actor), now()))
            event(conn, case_id, actor, 'note_added', {'initial': True})
        if model.snapshot_id is not None:
            _attach(conn, case_id, model.snapshot_id, actor)
        return record(conn, case_id)


def patch_case(case_id, model, actor):
    with write_transaction() as conn:
        row = record(conn, case_id, writable=True); check_version(row, model.expected_version)
        changes = model.model_dump(exclude_unset=True, exclude={'expected_version'})
        if 'assignee_user_id' in changes:
            validate_assignee(conn, changes['assignee_user_id'])
        conn.execute('UPDATE cases SET ' + ','.join(k+'=?' for k in changes) + ' WHERE id=?', (*changes.values(), case_id))
        bump(conn, case_id)
        event(conn, case_id, actor, 'edited', {'before': {k: row[k] for k in changes}, 'after': changes})
        return record(conn, case_id)


def transition(case_id, model, actor):
    with write_transaction() as conn:
        row = record(conn, case_id); check_version(row, model.expected_version)
        if row['is_archived'] or row['status'] == model.status:
            raise HTTPException(409, 'Restore the case first or choose a different status.')
        if model.status == 'closed' and actor['role'] != 'admin' and (actor.get('is_api_token') or row['assignee_user_id'] != actor.get('user_id')):
            raise HTTPException(403, 'Only the assigned human analyst or an administrator can close this case.')
        timestamp = now()
        conn.execute('UPDATE cases SET status=?,conclusion=?,closure_reason=?,closed_at=? WHERE id=?',
                     (model.status, model.conclusion, model.reason if model.status == 'closed' else None,
                      timestamp if model.status == 'closed' else None, case_id))
        bump(conn, case_id)
        event(conn, case_id, actor, 'transitioned', {'from': row['status'], 'to': model.status, 'conclusion': model.conclusion, 'reason': model.reason,
                                                  'previous_conclusion': row['conclusion'], 'previous_closure_reason': row['closure_reason']})
        return record(conn, case_id)


def add_note(case_id, model, actor):
    with write_transaction() as conn:
        row = record(conn, case_id, writable=True); check_version(row, model.expected_version)
        if conn.execute('SELECT COUNT(*) FROM case_notes WHERE case_id=?', (case_id,)).fetchone()[0] >= LIMITS['notes_per_case']:
            raise HTTPException(409, 'Case note limit reached.')
        if model.supersedes_note_id and not conn.execute('SELECT 1 FROM case_notes WHERE id=? AND case_id=?', (model.supersedes_note_id, case_id)).fetchone():
            raise HTTPException(422, 'Corrections must reference a note in this same case.')
        note_id = conn.execute('''INSERT INTO case_notes(case_id,body,supersedes_note_id,actor_user_id,actor_token_id,actor_name,created_at)
            VALUES (?,?,?,?,?,?,?)''', (case_id, model.body, model.supersedes_note_id, *actor_values(actor), now())).lastrowid
        bump(conn, case_id)
        event(conn, case_id, actor, 'note_added', {'note_id': note_id, 'supersedes_note_id': model.supersedes_note_id})
        return {'note_id': note_id, 'case': record(conn, case_id)}


def attach(case_id, model, actor):
    with write_transaction() as conn:
        row = record(conn, case_id, writable=True)
        authorized_snapshot(conn, model.snapshot_id, actor, require_integrity=True)
        duplicate = conn.execute('SELECT 1 FROM case_evidence WHERE case_id=? AND snapshot_id=?', (case_id, model.snapshot_id)).fetchone()
        if not duplicate:
            check_version(row, model.expected_version)
            _attach(conn, case_id, model.snapshot_id, actor); bump(conn, case_id)
        return {'attached': not bool(duplicate), 'case': record(conn, case_id)}


def reference_target(conn, kind, target_id):
    if kind == 'asset' and not config.FEATURE_ASSET_PRIORITIZATION:
        raise HTTPException(404, 'Asset inventory is disabled.')
    if kind == 'cve':
        target_id = target_id.upper()
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', target_id):
            raise HTTPException(422, 'Invalid CVE ID.')
        row = conn.execute('SELECT cve_id FROM cves WHERE cve_id=?', (target_id,)).fetchone()
        label = target_id
    else:
        if not target_id.isascii() or not target_id.isdigit() or int(target_id) < 1:
            raise HTTPException(422, 'Use an existing positive integer entity ID.')
        target_id = str(int(target_id))
        table, field = {'asset': ('assets', 'name'), 'actor': ('threat_actors', 'name'), 'rule': ('detection_rules', 'title')}[kind]
        row = conn.execute(f'SELECT {field} FROM {table} WHERE id=?', (target_id,)).fetchone()
        label = row[0] if row else ''
    if not row:
        raise HTTPException(404, 'Referenced entity not found.')
    return target_id, label


def add_reference(case_id, model, actor):
    with write_transaction() as conn:
        row = record(conn, case_id, writable=True); check_version(row, model.expected_version)
        target_id, label = reference_target(conn, model.kind, model.target_id)
        if conn.execute('SELECT 1 FROM case_references WHERE case_id=? AND kind=? AND target_id=?', (case_id, model.kind, target_id)).fetchone():
            return {'case': row, 'added': False}
        if conn.execute('SELECT COUNT(*) FROM case_references WHERE case_id=?', (case_id,)).fetchone()[0] >= LIMITS['references_per_case']:
            raise HTTPException(409, 'Case reference limit reached.')
        conn.execute('INSERT INTO case_references(case_id,kind,target_id,label,actor_user_id,actor_token_id,actor_name,created_at) VALUES (?,?,?,?,?,?,?,?)',
                     (case_id, model.kind, target_id, label, *actor_values(actor), now()))
        bump(conn, case_id)
        event(conn, case_id, actor, 'reference_added', {'kind': model.kind, 'target_id': target_id, 'label': label})
        return {'case': record(conn, case_id), 'added': True}


def archive(case_id, model, actor):
    with write_transaction() as conn:
        row = record(conn, case_id); check_version(row, model.expected_version)
        if bool(row['is_archived']) == model.archived:
            raise HTTPException(409, 'Archive state is unchanged.')
        conn.execute('UPDATE cases SET is_archived=? WHERE id=?', (int(model.archived), case_id))
        bump(conn, case_id)
        event(conn, case_id, actor, 'archived' if model.archived else 'restored', {'reason': model.reason})
        return record(conn, case_id)


def collection(case_id, kind, before_id=None, limit=50):
    table = {'notes': 'case_notes', 'evidence': 'case_evidence', 'references': 'case_references', 'events': 'case_events'}[kind]
    clause, args = 'case_id=?', [case_id]
    if before_id:
        clause += ' AND id<?'; args.append(before_id)
    with get_connection() as conn:
        record(conn, case_id)
        rows = conn.execute(f'SELECT * FROM {table} WHERE {clause} ORDER BY id DESC LIMIT ?', (*args, limit+1)).fetchall()
        items = []
        for row in rows[:limit]:
            item = dict(row)
            if kind == 'evidence':
                item['snapshot'] = snapshot_record(conn.execute('SELECT * FROM investigation_snapshots WHERE id=?', (row['snapshot_id'],)).fetchone())
            if kind == 'events':
                item['payload'] = json.loads(item.pop('payload_json'))
            if kind == 'references':
                try:
                    reference_target(conn, row['kind'], row['target_id']); item['available'] = True
                except HTTPException:
                    item['available'] = False
            items.append(item)
    return {'items': items, 'next_before_id': rows[limit-1]['id'] if len(rows)>limit else None}


def export_case(case_id, actor, format):
    # One read transaction captures a consistent report; no external lookups.
    with write_transaction() as conn:
        case = record(conn, case_id)
        report = {'schema_version': 1, 'classification': 'INTERNAL — SOC workspace; authorized recipients only',
                  'exported_at': now(), 'case': case, 'notes': [], 'evidence': [], 'references': [], 'events': [],
                  'notice': 'References are context, not frozen evidence or verified attribution. SHA-256 detects changes against the stored digest, not database-administrator tampering with both. This report is not a full database backup.'}
        for kind, table, maximum in (('notes', 'case_notes', LIMITS['notes_per_case']), ('evidence', 'case_evidence', LIMITS['evidence_per_case']),
                                     ('references', 'case_references', LIMITS['references_per_case']), ('events', 'case_events', LIMITS['events_per_case'])):
            rows = conn.execute(f'SELECT * FROM {table} WHERE case_id=? ORDER BY id LIMIT ?', (case_id, maximum+1)).fetchall()
            if len(rows) > maximum:
                raise HTTPException(413, 'Report exceeds supported collection limits; no partial export produced.')
            for row in rows:
                item = dict(row)
                if kind == 'evidence':
                    item['snapshot'] = snapshot_record(conn.execute('SELECT * FROM investigation_snapshots WHERE id=?', (row['snapshot_id'],)).fetchone())
                if kind == 'events':
                    item['payload'] = json.loads(item.pop('payload_json'))
                report[kind].append(item)
        data = json.dumps(report, ensure_ascii=False, indent=2)
        if len(data.encode()) > LIMITS['export_bytes']:
            raise HTTPException(413, 'Report exceeds the 12 MiB export limit; no truncation performed.')
        if format == 'markdown':
            # User content is encoded as inert indented code, never executable Markdown/HTML.
            data = f'# CyberDash case report — {case["reference"]}\n\nINTERNAL — SOC workspace; authorized recipients only.\n\n'
            data += '## Case summary\n\n' + markdown_text(canonical({k: case[k] for k in
                ('title', 'summary', 'status', 'severity', 'assignee_name', 'conclusion', 'closure_reason', 'created_at', 'updated_at')}))
            data += '\n## Analyst notes\n\n'
            for note in report['notes']:
                data += f'### Note {note["id"]}\n\n' + markdown_text(f'{note["created_at"]} — {note["actor_name"]}\n{note["body"]}')
            data += '\n## Preserved evidence\n\n'
            for item in report['evidence']:
                s = item['snapshot']
                data += f'### Snapshot {s["id"]}\n\n' + markdown_text(
                    f'{s["indicator"]}\nCaptured: {s["captured_at"]}\nSHA-256: {s["sha256"]}\n' +
                    ('Digest matches captured evidence.' if s['integrity_valid'] else s['warning']))
            data += '\n## Complete structured report and chronology\n\n'
            data += markdown_text(json.dumps(report, ensure_ascii=False, indent=2))
            if len(data.encode()) > LIMITS['export_bytes']:
                raise HTTPException(413, 'Markdown report exceeds 12 MiB; use JSON or review report size.')
        audit(conn, actor, 'CASE_EXPORTED', case_id, {'format': format})
    return data, case['reference']


def markdown_text(text):
    return '\n'.join('    ' + html.escape(line, quote=False) for line in text.splitlines()) + '\n\n'
