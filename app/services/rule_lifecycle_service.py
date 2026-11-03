"""Authoritative immutable rule snapshots; public and working read models stay separate."""
import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from fastapi import HTTPException
from app import config
from app.database import get_connection
from app.rule_migrations import FIELDS
from app.services.case_common import actor_values, actor_key, canonical, check_version, now
from app.services.audit_service import log_audit_event

LIMITS = {'rules': 500, 'revisions_per_rule': 50, 'snapshot_storage_bytes': 50*1024*1024,
          'validation_runs_per_revision': 20, 'events_per_rule': 500, 'source_bytes': 204800,
          'report_storage_bytes': 10*1024*1024, 'event_storage_bytes': 10*1024*1024, 'review_storage_bytes': 10*1024*1024}


@contextmanager
def write_transaction():
    try:
        with get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            yield conn
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, 'A rule title or linked-record conflict prevents this change; reload the rule.') from exc


def activated(conn):
    return bool(conn.execute("SELECT 1 FROM app_settings WHERE key='rule_lifecycle_activated' AND value='true'").fetchone())


def require_enabled():
    if not config.FEATURE_RULE_LIFECYCLE:
        raise HTTPException(404, 'Not found')


def legacy_writable(conn):
    if config.FEATURE_RULE_LIFECYCLE or activated(conn):
        raise HTTPException(409, 'Version-managed catalog: use lifecycle revisions/archive. Disabling the flag does not restore mutable CRUD.')


def identity(conn, rule_id, expected=None, writable=False):
    row = conn.execute('SELECT * FROM detection_rules WHERE id=? AND lifecycle_managed=1', (rule_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'Versioned rule not found.')
    if expected is not None:
        check_version(row, expected)
    if writable and row['is_archived']:
        raise HTTPException(409, 'Restore the archived rule before changing it.')
    return row


def raw_revision(conn, rule_id, revision_id):
    row = conn.execute('SELECT * FROM rule_revisions WHERE id=? AND rule_id=?', (revision_id, rule_id)).fetchone()
    if not row:
        raise HTTPException(404, 'Revision not found for this rule.')
    return row


def revision_payload(row):
    valid = hashlib.sha256(row['snapshot_json'].encode()).hexdigest() == row['sha256']
    try:
        payload = json.loads(row['snapshot_json'])
        if not isinstance(payload, dict) or set(payload) != set(FIELDS):
            valid = False; payload = {}
    except (ValueError, TypeError):
        valid = False; payload = {}
    return payload, valid


def require_integrity(row):
    payload, valid = revision_payload(row)
    if not valid:
        raise HTTPException(409, 'INTEGRITY WARNING: revision differs from its recorded digest.')
    return payload


def public_record(conn, row):
    if row['lifecycle_managed']:
        if row['is_archived'] or not row['published_revision_id']:
            return None
        rev = raw_revision(conn, row['id'], row['published_revision_id'])
        payload, valid = revision_payload(rev)
        if not valid:
            return None  # Never offer tampered source as a deployable download/catalog entry.
        return {**payload, 'id': row['id'], 'revision_id': rev['id'], 'revision_number': rev['revision_number'],
                'sha256': rev['sha256'], 'lifecycle_state': 'legacy_unreviewed' if rev['state']=='legacy_unreviewed' else 'published',
                'created_at': row['created_at'], 'updated_at': rev['created_at'],
                'notice': 'Legacy: unreviewed/unvalidated.' if rev['state']=='legacy_unreviewed' else 'Published after workflow review; syntax validation is not proof of detection efficacy.'}
    return {**dict(row), 'deployment_guide': row['deployment_guide'] or ''}


def public_rules(rule_type=None, search=None, siem=None):
    # New storage is bounded, but grandfathered legacy identities must not be
    # silently truncated. Filter only the public projection, never working data.
    result = []
    with get_connection() as conn:
        for row in conn.execute('SELECT * FROM detection_rules ORDER BY id'):
            value = public_record(conn, row)
            if not value:
                continue
            if rule_type and rule_type.upper() != 'ALL' and value['rule_type'].upper() != rule_type.upper():
                continue
            platform = (value.get('target_siem') or 'Generic').upper()
            if siem and siem.upper() != 'ALL' and siem.upper() not in platform and platform != 'GENERIC':
                continue
            if search and search.casefold() not in ' '.join(str(value.get(k) or '') for k in FIELDS).casefold():
                continue
            result.append(value)
    return result


def public_rule(rule_id):
    with get_connection() as conn:
        row = conn.execute('SELECT * FROM detection_rules WHERE id=?', (rule_id,)).fetchone()
        return public_record(conn, row) if row else None


def event(conn, rule_id, revision_id, actor, kind, details=None):
    if conn.execute('SELECT COUNT(*) FROM rule_lifecycle_events WHERE rule_id=?', (rule_id,)).fetchone()[0] >= LIMITS['events_per_rule']:
        raise HTTPException(409, 'Rule history capacity reached. Export/back up; history is never pruned automatically.')
    data=canonical(details or {})
    if conn.execute('SELECT COALESCE(SUM(length(CAST(details_json AS BLOB))),0) FROM rule_lifecycle_events').fetchone()[0]+len(data.encode())>LIMITS['event_storage_bytes']:
        raise HTTPException(409,'Rule event storage budget reached; export/back up. No history was deleted.')
    audit_id = log_audit_event(actor['username'], actor['role'], 'RULE_'+kind.upper(), resource_type='RULE', resource_id=str(rule_id),
        details=canonical({'revision_id': revision_id, 'actor_user_id': actor.get('user_id'), 'actor_token_id': actor.get('token_id')}),
        ip_address=actor.get('ip_address', 'unknown'), connection=conn)
    conn.execute('''INSERT INTO rule_lifecycle_events(rule_id,revision_id,kind,actor_user_id,actor_token_id,actor_name,details_json,audit_event_id,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)''', (rule_id, revision_id, kind, *actor_values(actor), data, audit_id, now()))


def revision_record(conn, row):
    payload, valid = revision_payload(row)
    validation = conn.execute('SELECT * FROM rule_validation_runs WHERE revision_id=? ORDER BY id DESC LIMIT 1', (row['id'],)).fetchone()
    result = {k: row[k] for k in ('id','rule_id','revision_number','parent_revision_id','author_user_id','author_token_id','author_name','state','created_at','sha256')}
    return {**result, 'snapshot': payload, 'integrity_valid': valid,
            'validation': {**dict(validation), 'report': json.loads(validation['report_json'])} if validation else None,
            'reviews': [dict(r) for r in conn.execute('SELECT * FROM rule_reviews WHERE revision_id=? ORDER BY id DESC LIMIT 20', (row['id'],))]}


def working_record(conn, row):
    return {**{k: row[k] for k in ('id','row_version','is_archived','published_revision_id','working_revision_id')},
            'working': revision_record(conn, raw_revision(conn, row['id'], row['working_revision_id']))}


def working(rule_id):
    require_enabled()
    with get_connection() as conn:
        return working_record(conn, identity(conn, rule_id))


def list_working(before_id=None, limit=20, archived=False):
    require_enabled()
    with get_connection() as conn:
        rows = conn.execute('SELECT * FROM detection_rules WHERE lifecycle_managed=1 AND is_archived=? AND id<? ORDER BY id DESC LIMIT ?',
                            (int(archived), before_id or 9223372036854775807, limit+1)).fetchall()
        return {'items': [working_record(conn,r) for r in rows[:limit]], 'next_before_id': rows[limit-1]['id'] if len(rows)>limit else None}


def add_revision(conn, rule_id, payload, parent_id, actor):
    count = conn.execute('SELECT COUNT(*) FROM rule_revisions WHERE rule_id=?', (rule_id,)).fetchone()[0]
    data = canonical(payload); size = len(data.encode())
    if count >= LIMITS['revisions_per_rule']:
        raise HTTPException(409, '50 retained revisions per rule. Export/back up; archive retains history and does not reclaim quota.')
    if conn.execute('SELECT COALESCE(SUM(payload_bytes),0) FROM rule_revisions').fetchone()[0] + size > LIMITS['snapshot_storage_bytes']:
        raise HTTPException(409, '50 MiB retained snapshot budget reached. Export/back up and review storage; no history was deleted.')
    revision_id = conn.execute('''INSERT INTO rule_revisions(rule_id,revision_number,parent_revision_id,snapshot_json,sha256,payload_bytes,
        author_key,author_user_id,author_token_id,author_name,state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,'draft',?)''',
        (rule_id, count+1, parent_id, data, hashlib.sha256(data.encode()).hexdigest(), size, actor_key(actor), *actor_values(actor), now())).lastrowid
    conn.execute('UPDATE detection_rules SET working_revision_id=?,row_version=row_version+1,updated_at=? WHERE id=?', (revision_id,now(),rule_id))
    return revision_id


def create(payload, actor):
    require_enabled()
    with write_transaction() as conn:
        if conn.execute('SELECT COUNT(*) FROM detection_rules').fetchone()[0] >= LIMITS['rules']:
            raise HTTPException(409, 'At most 500 retained rule identities.')
        rule_id = conn.execute("INSERT INTO detection_rules(title,rule_type,code_content,lifecycle_managed,row_version) VALUES (?,'Sigma','',1,0)",
                               ('Private identity '+uuid.uuid4().hex,)).lastrowid
        rev = add_revision(conn,rule_id,payload,None,actor)
        event(conn,rule_id,rev,actor,'draft_created')
        return working_record(conn,identity(conn,rule_id))


def new_revision(rule_id, body, actor):
    require_enabled()
    with write_transaction() as conn:
        row = identity(conn,rule_id,body.expected_version,True)
        if row['working_revision_id'] != body.expected_parent_revision_id:
            raise HTTPException(409,'Working parent changed; reload before creating a revision.')
        parent = raw_revision(conn,rule_id,row['working_revision_id'])
        if parent['state'] in ('in_review','approved'):
            raise HTTPException(409,'Withdraw the frozen candidate to a new draft before editing.')
        revision_id = add_revision(conn,rule_id,body.model_dump(exclude={'expected_version','expected_parent_revision_id'}),parent['id'],actor)
        event(conn,rule_id,revision_id,actor,'revision_created')
        return working_record(conn,identity(conn,rule_id))


def current_candidate(conn, rule_id, revision_id, expected):
    row = identity(conn,rule_id,expected,True)
    if row['working_revision_id'] != revision_id:
        raise HTTPException(409,'Only the current working revision can change workflow state.')
    rev = raw_revision(conn,rule_id,revision_id); require_integrity(rev)
    return row, rev


def valid_report(conn, rev, validation_id=None):
    from app.services.rule_validation_service import validator_version
    run = conn.execute('SELECT * FROM rule_validation_runs WHERE revision_id=? AND (? IS NULL OR id=?) ORDER BY id DESC LIMIT 1',
                       (rev['id'],validation_id,validation_id)).fetchone()
    if not run or run['status']!='valid' or run['revision_hash']!=rev['sha256'] or run['validator_version']!=validator_version(require_integrity(rev)['rule_type']):
        raise HTTPException(409,'The exact revision needs a valid report from the current validator policy.')
    return run


def human_admin(conn, actor, author_key=None):
    user_id = actor.get('user_id')
    if actor.get('is_api_token') or not user_id or actor['role']!='admin' or not conn.execute("SELECT 1 FROM users WHERE id=? AND role='admin'",(user_id,)).fetchone():
        raise HTTPException(403,'Independent review/publication requires a current human administrator, not a machine token.')
    if author_key == actor_key(actor):
        raise HTTPException(403,'The revision author cannot approve or reject their own candidate; use a different human administrator.')


def submit(rule_id, revision_id, body, actor):
    require_enabled()
    with write_transaction() as conn:
        row,rev = current_candidate(conn,rule_id,revision_id,body.expected_version)
        if rev['state']!='draft': raise HTTPException(409,'Only a draft can be submitted.')
        run = valid_report(conn,rev)
        conn.execute("UPDATE rule_revisions SET state='in_review',submitted_validation_id=? WHERE id=?",(run['id'],revision_id))
        conn.execute('UPDATE detection_rules SET row_version=row_version+1 WHERE id=?',(rule_id,))
        event(conn,rule_id,revision_id,actor,'submitted',{'validation_id':run['id']})
        return working_record(conn,identity(conn,rule_id))


def review(rule_id,revision_id,body,actor):
    require_enabled()
    with write_transaction() as conn:
        row,rev = current_candidate(conn,rule_id,revision_id,body.expected_version)
        human_admin(conn,actor,rev['author_key'])
        if rev['state']!='in_review': raise HTTPException(409,'Only a frozen review candidate can be reviewed.')
        run = valid_report(conn,rev,rev['submitted_validation_id'])
        if conn.execute('SELECT COALESCE(SUM(length(CAST(reason AS BLOB))),0) FROM rule_reviews').fetchone()[0]+len(body.reason.encode())>LIMITS['review_storage_bytes']:
            raise HTTPException(409,'Rule review storage budget reached; export/back up. No reviews were deleted.')
        conn.execute('''INSERT INTO rule_reviews(revision_id,validation_id,revision_hash,reviewer_user_id,reviewer_key,reviewer_name,decision,reason,created_at)
            VALUES (?,?,?,?,?,?,?,?,?)''',(revision_id,run['id'],rev['sha256'],actor['user_id'],actor_key(actor),actor['username'],body.decision,body.reason,now()))
        conn.execute('UPDATE rule_revisions SET state=? WHERE id=?',(body.decision,revision_id))
        conn.execute('UPDATE detection_rules SET row_version=row_version+1 WHERE id=?',(rule_id,))
        event(conn,rule_id,revision_id,actor,body.decision,{'reason':body.reason,'validation_id':run['id']})
        return working_record(conn,identity(conn,rule_id))


def publish(rule_id,revision_id,body,actor):
    require_enabled()
    with write_transaction() as conn:
        human_admin(conn,actor)
        row,rev = current_candidate(conn,rule_id,revision_id,body.expected_version)
        if rev['state']!='approved': raise HTTPException(409,'Only an independently approved candidate may be published.')
        run = valid_report(conn,rev,rev['submitted_validation_id'])
        approval = conn.execute("SELECT * FROM rule_reviews WHERE revision_id=? AND decision='approved' ORDER BY id DESC LIMIT 1",(revision_id,)).fetchone()
        if (not approval or approval['validation_id']!=run['id'] or approval['revision_hash']!=rev['sha256'] or approval['reviewer_key']==rev['author_key']
                or not conn.execute("SELECT 1 FROM users WHERE id=? AND role='admin'",(approval['reviewer_user_id'],)).fetchone()):
            raise HTTPException(409,'Independent approval is missing, stale or its reviewer is no longer an administrator.')
        payload = require_integrity(rev)
        conn.execute('UPDATE detection_rules SET '+','.join(k+'=?' for k in FIELDS)+',published_revision_id=?,row_version=row_version+1,updated_at=? WHERE id=?',
                     (*[payload[k] for k in FIELDS],revision_id,now(),rule_id))
        conn.execute("UPDATE rule_revisions SET state='published' WHERE id=?",(revision_id,))
        event(conn,rule_id,revision_id,actor,'published',{'previous_published_revision_id':row['published_revision_id']})
        return working_record(conn,identity(conn,rule_id))


def derive(rule_id,body,actor,withdraw_revision_id=None):
    require_enabled()
    with write_transaction() as conn:
        row = identity(conn,rule_id,body.expected_version,True)
        parent = raw_revision(conn,rule_id,row['working_revision_id'])
        if withdraw_revision_id is not None:
            if parent['id']!=withdraw_revision_id or parent['state'] not in ('in_review','approved'):
                raise HTTPException(409,'Withdraw the current review/approved candidate only.')
            source = parent
            conn.execute("UPDATE rule_revisions SET state='withdrawn' WHERE id=?",(parent['id'],))
        else:
            if parent['state'] in ('in_review','approved'): raise HTTPException(409,'Withdraw the frozen candidate before rollback.')
            source = raw_revision(conn,rule_id,body.source_revision_id)
        revision_id = add_revision(conn,rule_id,require_integrity(source),parent['id'],actor)
        event(conn,rule_id,revision_id,actor,'withdrawn_to_draft' if withdraw_revision_id else 'rollback_draft',{'source_revision_id':source['id'],'reason':body.reason})
        return working_record(conn,identity(conn,rule_id))


def archive(rule_id,body,actor):
    require_enabled()
    if actor['role']!='admin': raise HTTPException(403,'Administrator required.')
    with write_transaction() as conn:
        row=identity(conn,rule_id,body.expected_version)
        if bool(row['is_archived'])==body.archived: raise HTTPException(409,'Archive state unchanged.')
        conn.execute('UPDATE detection_rules SET is_archived=?,row_version=row_version+1 WHERE id=?',(int(body.archived),rule_id))
        event(conn,rule_id,row['working_revision_id'],actor,'archived' if body.archived else 'restored',{'reason':body.reason})
        return working_record(conn,identity(conn,rule_id))


def history(rule_id,before_id=None,limit=20):
    require_enabled()
    with get_connection() as conn:
        identity(conn,rule_id)
        rows=conn.execute('SELECT * FROM rule_revisions WHERE rule_id=? AND id<? ORDER BY id DESC LIMIT ?',(rule_id,before_id or 9223372036854775807,limit+1)).fetchall()
        return {'items':[revision_record(conn,r) for r in rows[:limit]],'next_before_id':rows[limit-1]['id'] if len(rows)>limit else None}


def get_revision(rule_id,revision_id):
    require_enabled()
    with get_connection() as conn:
        identity(conn,rule_id)
        return revision_record(conn,raw_revision(conn,rule_id,revision_id))
