"""Private authoring/review APIs and a separately authorized public source download."""
import difflib
import json
from fastapi import Depends, Query, Request, HTTPException
from fastapi.responses import Response
from app import config
from app.asset_security import csrf_token,protect_mutation
from app.database import get_connection
from app.models.rule_schemas import (RuleSnapshot,RevisionRequest,RuleAction,RuleReview,RuleRollback,RuleArchive,WorkingRule,RulePage,RevisionRecord)
from app.services import rule_lifecycle_service as rules,rule_validation_service as validation


def register_rule_routes(app,templates,auth_context,analyst,admin):
    @app.get('/api/detection-rules/{rule_id}/download')
    def download(rule_id:int):
        rule=rules.public_rule(rule_id)
        if not rule: raise HTTPException(404,'Published/legacy rule not found.')
        comment='#' if rule['rule_type'].upper()=='SIGMA' else '//'
        prefix=comment+' '+rule.get('notice','Legacy, unreviewed/unvalidated rule.')+'\n'
        prefix+=f'{comment} Rule {rule_id}; revision {rule.get("revision_number","unversioned")}; SHA-256 {rule.get("sha256","not captured")}\n'
        extension='yml' if rule['rule_type'].upper()=='SIGMA' else 'yar'
        return Response(prefix+(rule['code_content'] or ''),media_type='text/plain',headers={
            'Content-Disposition':f'attachment; filename="rule-{rule_id}-r{rule.get("revision_number",0)}.{extension}"',
            'X-Rule-Revision':str(rule.get('revision_id','unversioned')),'X-Rule-SHA256':rule.get('sha256','unversioned')})

    if not config.FEATURE_RULE_LIFECYCLE: return

    def mutation(request:Request,actor=Depends(analyst)):
        protect_mutation(request,actor)
        return {**actor,'ip_address':request.client.host if request.client else 'unknown'}

    @app.get('/api/rule-lifecycle/rules',response_model=RulePage)
    def list_rules(before_id:int|None=Query(None,ge=1),limit:int=Query(20,ge=1,le=50),archived:bool=False,actor=Depends(analyst)):
        return rules.list_working(before_id,limit,archived)

    @app.post('/api/rule-lifecycle/rules',status_code=201,response_model=WorkingRule)
    def create(body:RuleSnapshot,actor=Depends(mutation)):
        return rules.create(body.model_dump(),actor)

    @app.get('/api/detection-rules/{rule_id}/working',response_model=WorkingRule)
    def working(rule_id:int,actor=Depends(analyst)):
        return rules.working(rule_id)

    @app.post('/api/detection-rules/{rule_id}/revisions',status_code=201,response_model=WorkingRule)
    def revision(rule_id:int,body:RevisionRequest,actor=Depends(mutation)):
        return rules.new_revision(rule_id,body,actor)

    @app.get('/api/detection-rules/{rule_id}/revisions',response_model=RulePage)
    def history(rule_id:int,before_id:int|None=Query(None,ge=1),limit:int=Query(20,ge=1,le=50),actor=Depends(analyst)):
        return rules.history(rule_id,before_id,limit)

    @app.get('/api/detection-rules/{rule_id}/revisions/export')
    def export(rule_id:int,actor=Depends(analyst)):
        with rules.write_transaction() as conn:
            row=rules.identity(conn,rule_id)
            revisions=conn.execute('SELECT * FROM rule_revisions WHERE rule_id=? ORDER BY id DESC LIMIT 51',(rule_id,)).fetchall()
            if len(revisions)>50: raise HTTPException(413,'History exceeds the 50-revision export limit; no truncation performed.')
            data={'schema_version':1,'rule':rules.working_record(conn,row),'revisions':[rules.revision_record(conn,r) for r in revisions],
                  'notice':'INTERNAL authoring history. Not a deployable bundle. Restoring this export never bypasses review.'}
            data['validations']=[dict(r) for r in conn.execute('''SELECT v.* FROM rule_validation_runs v JOIN rule_revisions r ON r.id=v.revision_id
                WHERE r.rule_id=? ORDER BY v.id LIMIT 1001''',(rule_id,))]
            data['events']=[dict(r) for r in conn.execute('SELECT * FROM rule_lifecycle_events WHERE rule_id=? ORDER BY id LIMIT 501',(rule_id,))]
            if len(data['validations'])>1000 or len(data['events'])>500:
                raise HTTPException(413,'Report collection limits exceeded; no truncation performed.')
            content=json.dumps(data,ensure_ascii=False,indent=2)
            if len(content.encode())>20*1024*1024: raise HTTPException(413,'History export exceeds 20 MiB; export individual revision pages.')
            rules.log_audit_event(actor['username'],actor['role'],'RULE_HISTORY_EXPORTED',resource_type='RULE',resource_id=str(rule_id),
                details=json.dumps({'actor_user_id':actor.get('user_id'),'actor_token_id':actor.get('token_id')}),connection=conn)
        return Response(content,media_type='application/json',headers={'Content-Disposition':f'attachment; filename="rule-{rule_id}-history-v1.json"'})

    @app.get('/api/detection-rules/{rule_id}/revisions/{revision_id}',response_model=RevisionRecord)
    def get_revision(rule_id:int,revision_id:int,actor=Depends(analyst)):
        return rules.get_revision(rule_id,revision_id)

    @app.get('/api/detection-rules/{rule_id}/diff')
    def diff(rule_id:int,older:int=Query(ge=1),newer:int=Query(ge=1),actor=Depends(analyst))->dict:
        before=rules.get_revision(rule_id,older); after=rules.get_revision(rule_id,newer)
        def diff_lines(snapshot):
            return (json.dumps({k:v for k,v in snapshot.items() if k!='code_content'},ensure_ascii=False,indent=2)+'\n\nSource:\n'+snapshot.get('code_content','')).splitlines()
        text='\n'.join(difflib.unified_diff(diff_lines(before['snapshot']),diff_lines(after['snapshot']),
             fromfile=f'revision-{older}',tofile=f'revision-{newer}',lineterm=''))
        return {'older_integrity_valid':before['integrity_valid'],'newer_integrity_valid':after['integrity_valid'],'diff':text}

    @app.post('/api/detection-rules/{rule_id}/revisions/{revision_id}/validate')
    def validate(rule_id:int,revision_id:int,body:RuleAction,actor=Depends(mutation))->dict:
        return validation.validate(rule_id,revision_id,body,actor)

    @app.post('/api/detection-rules/{rule_id}/revisions/{revision_id}/submit',response_model=WorkingRule)
    def submit(rule_id:int,revision_id:int,body:RuleAction,actor=Depends(mutation)):
        return rules.submit(rule_id,revision_id,body,actor)

    @app.post('/api/detection-rules/{rule_id}/revisions/{revision_id}/withdraw',response_model=WorkingRule)
    def withdraw(rule_id:int,revision_id:int,body:RuleAction,actor=Depends(mutation)):
        return rules.derive(rule_id,body,actor,revision_id)

    @app.post('/api/detection-rules/{rule_id}/revisions/{revision_id}/review',response_model=WorkingRule)
    def review(rule_id:int,revision_id:int,body:RuleReview,user=Depends(admin),actor=Depends(mutation)):
        return rules.review(rule_id,revision_id,body,actor)

    @app.post('/api/detection-rules/{rule_id}/revisions/{revision_id}/publish',response_model=WorkingRule)
    def publish(rule_id:int,revision_id:int,body:RuleAction,user=Depends(admin),actor=Depends(mutation)):
        return rules.publish(rule_id,revision_id,body,actor)

    @app.post('/api/detection-rules/{rule_id}/rollback',response_model=WorkingRule)
    def rollback(rule_id:int,body:RuleRollback,actor=Depends(mutation)):
        return rules.derive(rule_id,body,actor)

    @app.post('/api/detection-rules/{rule_id}/archive',response_model=WorkingRule)
    def archive(rule_id:int,body:RuleArchive,user=Depends(admin),actor=Depends(mutation)):
        return rules.archive(rule_id,body,actor)

    @app.get('/rule-workbench',include_in_schema=False)
    def workbench(request:Request,user=Depends(analyst)):
        return templates.TemplateResponse(request=request,name='rule_workbench.html',context={
            'request':request,**auth_context(request),'rule_csrf_token':csrf_token(request),'rule_id':None,'rule_user_id':user.get('user_id')})

    @app.get('/rule-workbench/{rule_id}',include_in_schema=False)
    def workbench_detail(request:Request,rule_id:int,user=Depends(analyst)):
        rules.working(rule_id)
        return templates.TemplateResponse(request=request,name='rule_workbench.html',context={
            'request':request,**auth_context(request),'rule_csrf_token':csrf_token(request),'rule_id':rule_id,'rule_user_id':user.get('user_id')})
