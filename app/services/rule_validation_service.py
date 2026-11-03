"""Bounded local validators, with shared SQLite capacity claims and immutable reports."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import uuid
from importlib.metadata import PackageNotFoundError, version
from fastapi import HTTPException
from app.services import rule_lifecycle_service as lifecycle
from app.services.case_common import actor_values, canonical, now

NOTICE='Syntax/structure validation is not proof of detection efficacy or SIEM compatibility.'


def validator_version(rule_type):
    packages=('pysigma','PyYAML') if rule_type.upper()=='SIGMA' else ('yara-python',)
    values=[]
    for name in packages:
        try: value=version(name)
        except PackageNotFoundError: value='missing'
        values.append(name+'='+value)
    return 'policy-1/'+'/'.join(values)


def run_validator(snapshot):
    started=time.monotonic(); fingerprint=validator_version(snapshot['rule_type'])
    result={'status':'error','reason':'worker_crash','errors':[],'warnings':[NOTICE],'validator_version':fingerprint}
    env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'}
    process=None
    try:
        process=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve().parents[1]/'rule_validator_process.py')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,start_new_session=True,close_fds=True)
        pending=memoryview(canonical({'snapshot':snapshot,'validator_version':fingerprint}).encode())
        os.set_blocking(process.stdin.fileno(),False)
        deadline=started+3; output=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            selector.register(process.stdin,selectors.EVENT_WRITE)
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    result['reason']='timeout'; break
                complete=False
                for key,_ in selector.select(min(.1,remaining)):
                    if key.fileobj is process.stdin:
                        try:
                            written=os.write(process.stdin.fileno(),pending[:4096])
                        except BlockingIOError:
                            continue
                        pending=pending[written:]
                        if not pending:
                            selector.unregister(process.stdin); process.stdin.close()
                        continue
                    chunk=os.read(process.stdout.fileno(),8192)
                    if not chunk:
                        process.wait(timeout=max(.01,deadline-time.monotonic()))
                        if process.returncode==0:
                            data=json.loads(output)
                            if (isinstance(data,dict) and data.get('status') in ('valid','invalid','error')
                                    and data.get('validator_version')==fingerprint and isinstance(data.get('reason'),str)
                                    and isinstance(data.get('errors'),list) and isinstance(data.get('warnings'),list)):
                                result=data
                        complete=True; break
                    output.extend(chunk)
                    if len(output)>32768:
                        result['reason']='output_limit'; complete=True; break
                if complete: break
    except subprocess.TimeoutExpired:
        result['reason']='timeout'
    except (OSError,ValueError,TypeError):
        result['reason']='worker_crash'
    finally:
        if process:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
            if process.stdin and not process.stdin.closed: process.stdin.close()
            process.stdout.close()
    return {**result,'duration_ms':round((time.monotonic()-started)*1000,2)}


def validate(rule_id,revision_id,body,actor):
    lifecycle.require_enabled(); owner=uuid.uuid4().hex
    with lifecycle.write_transaction() as conn:
        row=lifecycle.identity(conn,rule_id,body.expected_version,True)
        rev=lifecycle.raw_revision(conn,rule_id,revision_id); payload=lifecycle.require_integrity(rev)
        if rev['state'] not in ('draft','legacy_unreviewed','rejected'):
            raise HTTPException(409,'Frozen review/published revisions cannot be revalidated; create a new draft.')
        if conn.execute('SELECT COUNT(*) FROM rule_validation_runs WHERE revision_id=?',(revision_id,)).fetchone()[0]>=lifecycle.LIMITS['validation_runs_per_revision']:
            raise HTTPException(409,'20 validation reports per revision; create a new draft or export/back up.')
        conn.execute('DELETE FROM rule_validation_claims WHERE expires_at<=?',(time.time(),))
        if conn.execute('SELECT 1 FROM rule_validation_claims WHERE revision_id=?',(revision_id,)).fetchone():
            raise HTTPException(409,'This revision is already being validated.')
        slots={r[0] for r in conn.execute('SELECT slot FROM rule_validation_claims')}
        available=next((n for n in (1,2) if n not in slots),None)
        if available is None: raise HTTPException(503,'Both validator slots are busy; retry shortly.',headers={'Retry-After':'5'})
        conn.execute('INSERT INTO rule_validation_claims VALUES (?,?,?,?)',(available,revision_id,owner,time.time()+15))
    try:
        report=run_validator(payload)
        with lifecycle.write_transaction() as conn:
            claim=conn.execute('SELECT 1 FROM rule_validation_claims WHERE owner=? AND expires_at>?',(owner,time.time())).fetchone()
            if not claim: raise HTTPException(409,'Validation claim expired; no valid report was recorded.')
            fresh=lifecycle.raw_revision(conn,rule_id,revision_id)
            if fresh['sha256']!=rev['sha256'] or fresh['snapshot_json']!=rev['snapshot_json']:
                raise HTTPException(409,'Revision integrity changed during validation.')
            data=canonical(report)
            if conn.execute('SELECT COALESCE(SUM(length(CAST(report_json AS BLOB))),0) FROM rule_validation_runs').fetchone()[0]+len(data.encode())>lifecycle.LIMITS['report_storage_bytes']:
                raise HTTPException(409,'Validation report storage budget reached; export/back up. No reports were deleted.')
            validation_id=conn.execute('''INSERT INTO rule_validation_runs(revision_id,revision_hash,validator_version,status,report_json,duration_ms,
                actor_user_id,actor_token_id,actor_name,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (revision_id,rev['sha256'],report['validator_version'],report['status'],data,report['duration_ms'],*actor_values(actor),now())).lastrowid
            lifecycle.event(conn,rule_id,revision_id,actor,'validated',{'validation_id':validation_id,'status':report['status'],'reason':report['reason']})
        return {'id':validation_id,'revision_id':revision_id,'revision_hash':rev['sha256'],'report':report}
    finally:
        with lifecycle.write_transaction() as conn: conn.execute('DELETE FROM rule_validation_claims WHERE owner=?',(owner,))
