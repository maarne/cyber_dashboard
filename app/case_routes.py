"""Case routes share existing RBAC; no guest/viewer topology, exports or counts."""
from datetime import date, timedelta
from typing import Literal
from fastapi import Depends, Query, Request
from fastapi.responses import Response
from app.asset_security import csrf_token, protect_mutation
from app.models.case_schemas import (CaseCreate, CasePatch, CaseTransition, CaseNote, CaseEvidence, CaseReference,
                                     CaseArchive, CaseRecord, CasePage, InvestigationRequest, InvestigationResponse, SnapshotRecord,
                                     CaseMutationResponse, CaseCollection)
from app.services import case_service as cases, investigation_snapshot_service as snapshots


def register_case_routes(app, templates, auth_context, analyst, admin):
    def mutation(request: Request, actor=Depends(analyst)):
        protect_mutation(request, actor)
        return {**actor, 'ip_address': request.client.host if request.client else 'unknown'}

    @app.get('/api/cases/assignees')
    def assignees(actor=Depends(analyst)) -> dict:
        return cases.assignees()

    @app.get('/api/cases', response_model=CasePage)
    def list_cases(search: str = Query('', max_length=200), indicator: str = Query('', max_length=2048),
                   status: Literal['', 'open', 'in_progress', 'closed'] = '', severity: Literal['', 'low', 'medium', 'high', 'critical'] = '',
                   assignee_user_id: int | None = Query(None, ge=1), archived: bool = False,
                   created_from: date | None = None, created_to: date | None = None,
                   reference_kind: Literal['', 'asset', 'cve', 'actor', 'rule'] = '', target_id: str = Query('', max_length=100),
                   before_id: int | None = Query(None, ge=1), limit: int = Query(50, ge=1, le=100), actor=Depends(analyst)):
        return cases.list_cases(search=search, indicator=indicator, status=status, severity=severity, assignee_user_id=assignee_user_id,
            archived=archived, created_from=created_from.isoformat() if created_from else '',
            created_to=(created_to+timedelta(days=1)).isoformat() if created_to and created_to < date.max else '',
            reference_kind=reference_kind, target_id=target_id, before_id=before_id, limit=limit)

    @app.post('/api/cases', status_code=201, response_model=CaseRecord)
    def create_case(body: CaseCreate, actor=Depends(mutation)):
        return cases.create(body, actor)

    @app.get('/api/cases/{case_id}', response_model=CaseRecord)
    def get_case(case_id: int, actor=Depends(analyst)):
        return cases.get_case(case_id)

    @app.patch('/api/cases/{case_id}', response_model=CaseRecord)
    def edit_case(case_id: int, body: CasePatch, actor=Depends(mutation)):
        return cases.patch_case(case_id, body, actor)

    @app.post('/api/cases/{case_id}/transition', response_model=CaseRecord)
    def transition(case_id: int, body: CaseTransition, actor=Depends(mutation)):
        return cases.transition(case_id, body, actor)

    @app.post('/api/cases/{case_id}/notes', response_model=CaseMutationResponse, response_model_exclude_none=True)
    def add_note(case_id: int, body: CaseNote, actor=Depends(mutation)) -> dict:
        return cases.add_note(case_id, body, actor)

    @app.post('/api/cases/{case_id}/evidence', response_model=CaseMutationResponse, response_model_exclude_none=True)
    def evidence(case_id: int, body: CaseEvidence, actor=Depends(mutation)) -> dict:
        return cases.attach(case_id, body, actor)

    @app.post('/api/cases/{case_id}/references', response_model=CaseMutationResponse, response_model_exclude_none=True)
    def reference(case_id: int, body: CaseReference, actor=Depends(mutation)) -> dict:
        return cases.add_reference(case_id, body, actor)

    @app.get('/api/cases/{case_id}/notes', response_model=CaseCollection)
    def notes(case_id: int, before_id: int | None = Query(None, ge=1), limit: int = Query(50, ge=1, le=100), actor=Depends(analyst)) -> dict:
        return cases.collection(case_id, 'notes', before_id, limit)

    @app.get('/api/cases/{case_id}/evidence', response_model=CaseCollection)
    def evidence_list(case_id: int, before_id: int | None = Query(None, ge=1), limit: int = Query(10, ge=1, le=25), actor=Depends(analyst)) -> dict:
        return cases.collection(case_id, 'evidence', before_id, limit)

    @app.get('/api/cases/{case_id}/references', response_model=CaseCollection)
    def references(case_id: int, before_id: int | None = Query(None, ge=1), limit: int = Query(50, ge=1, le=100), actor=Depends(analyst)) -> dict:
        return cases.collection(case_id, 'references', before_id, limit)

    @app.get('/api/cases/{case_id}/events', response_model=CaseCollection)
    def events(case_id: int, before_id: int | None = Query(None, ge=1), limit: int = Query(50, ge=1, le=100), actor=Depends(analyst)) -> dict:
        return cases.collection(case_id, 'events', before_id, limit)

    @app.post('/api/cases/{case_id}/archive', response_model=CaseRecord)
    def archive(case_id: int, body: CaseArchive, user=Depends(admin), actor=Depends(mutation)):
        return cases.archive(case_id, body, actor)

    @app.get('/api/cases/{case_id}/export')
    def export(case_id: int, format: Literal['json', 'markdown'] = 'json', actor=Depends(analyst)):
        data, reference = cases.export_case(case_id, actor, format)
        return Response(data, media_type='application/json' if format == 'json' else 'text/markdown', headers={
            'Content-Disposition': f'attachment; filename="{reference}-v1.{"json" if format == "json" else "md"}"'})

    @app.post('/api/investigations', status_code=201, response_model=InvestigationResponse)
    def investigate(body: InvestigationRequest, actor=Depends(mutation)):
        return snapshots.capture(body, actor)

    @app.get('/api/investigations/{snapshot_id}', response_model=SnapshotRecord)
    def result(snapshot_id: int, actor=Depends(analyst)):
        return snapshots.get_snapshot(snapshot_id, actor)

    @app.get('/cases', include_in_schema=False)
    def case_page(request: Request, actor=Depends(analyst)):
        return templates.TemplateResponse(request=request, name='cases.html', context={
            'request': request, **auth_context(request), 'case_csrf_token': csrf_token(request)})

    @app.get('/cases/{case_id}', include_in_schema=False)
    def case_detail(request: Request, case_id: int, actor=Depends(analyst)):
        return templates.TemplateResponse(request=request, name='case_detail.html', context={
            'request': request, **auth_context(request), 'case_csrf_token': csrf_token(request), 'case': cases.get_case(case_id)})
