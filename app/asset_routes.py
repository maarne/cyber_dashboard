"""Feature 1 routes, registered with the existing RBAC dependencies."""

from typing import Literal

from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse, Response

from app.asset_security import csrf_token, protect_mutation
from app.models.asset_schemas import (ArchiveRequest, AssetCreate, AssetPatch, AssessmentCreate, AssessmentPatch,
                                      ImportCommitRequest, ImportPreviewRequest, SoftwareCreate, SoftwarePatch, VersionRequest,
                                      AssetRecord, AssetPage, SoftwareRecord, SoftwarePage, AssessmentRecord, PriorityPage)
from app.services import asset_service as assets
from app.services.prioritization_service import list_priorities


def register_asset_routes(app, templates, auth_context, authenticated, analyst, admin):
    # Register directly, matching this app's route-based explorer on both old
    # FastAPI releases and releases that retain included routers as lazy nodes.
    router = app

    def mutation(request: Request, actor=Depends(authenticated)):
        protect_mutation(request, actor)
        return {**actor, "ip_address": request.client.host if request.client else "unknown"}

    @router.get("/api/assets", response_model=AssetPage)
    def inventory(search: str = Query("", max_length=200), environment: str = Query("", max_length=40),
                  tag: str = Query("", max_length=32), archived: bool = False,
                  limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)):
        return assets.list_assets(search=search, environment=environment, tag=tag, archived=archived, limit=limit, offset=offset)

    # Static paths must precede /{asset_id}.
    @router.get("/api/assets/export")
    def export(format: Literal["json", "csv"] = "json", user=Depends(admin)):
        data = assets.export_inventory(user)
        headers = {"Content-Disposition": f'attachment; filename="cyberdash-inventory-v1.{format}"'}
        return (Response(assets.inventory_csv(data), media_type="text/csv", headers=headers) if format == "csv"
                else JSONResponse(data, headers=headers))

    @router.get("/api/assets/import/template")
    def template(user=Depends(admin)):
        return Response(assets.csv_template(), media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="cyberdash-import-v1.csv"'})

    @router.post("/api/assets/import/preview")
    def preview(body: ImportPreviewRequest, user=Depends(admin), actor=Depends(mutation)):
        return assets.preview_import(body.csv_content, actor)

    @router.post("/api/assets/import/commit")
    def commit(body: ImportCommitRequest, user=Depends(admin), actor=Depends(mutation)):
        return assets.commit_import(body.preview_token, actor)

    @router.get("/api/assets/session")
    def session(request: Request, user=Depends(authenticated)):
        return {"csrf_token": csrf_token(request), "role": user["role"]}

    @router.post("/api/assets", status_code=201, response_model=AssetRecord)
    def create(body: AssetCreate, user=Depends(analyst), actor=Depends(mutation)):
        return assets.create_asset(body.model_dump(mode="json"), actor)

    @router.get("/api/assets/{asset_id}", response_model=AssetRecord)
    def detail(asset_id: int, user=Depends(authenticated)):
        return assets.get_asset(asset_id)

    @router.patch("/api/assets/{asset_id}", response_model=AssetRecord)
    def update(asset_id: int, body: AssetPatch, user=Depends(analyst), actor=Depends(mutation)):
        return assets.update_asset(asset_id, body.model_dump(mode="json", exclude_unset=True), actor)

    @router.post("/api/assets/{asset_id}/archive", response_model=AssetRecord)
    def archive(asset_id: int, body: ArchiveRequest, user=Depends(admin), actor=Depends(mutation)):
        return assets.archive_asset(asset_id, body.model_dump(), actor)

    @router.get("/api/assets/{asset_id}/software", response_model=SoftwarePage)
    def software(asset_id: int, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)):
        return assets.list_software(asset_id, limit=limit, offset=offset)

    @router.post("/api/assets/{asset_id}/software", status_code=201, response_model=SoftwareRecord)
    def add_software(asset_id: int, body: SoftwareCreate, user=Depends(analyst), actor=Depends(mutation)):
        return assets.create_software(asset_id, body.model_dump(mode="json"), actor)

    @router.patch("/api/assets/{asset_id}/software/{software_id}", response_model=SoftwareRecord)
    def edit_software(asset_id: int, software_id: int, body: SoftwarePatch, user=Depends(analyst), actor=Depends(mutation)):
        return assets.change_software(asset_id, software_id, body.model_dump(mode="json", exclude_unset=True), actor)

    @router.delete("/api/assets/{asset_id}/software/{software_id}")
    def delete_software(asset_id: int, software_id: int, body: VersionRequest, user=Depends(analyst), actor=Depends(mutation)):
        return assets.change_software(asset_id, software_id, body.model_dump(), actor, delete=True)

    @router.get("/api/assets/{asset_id}/cves", response_model=PriorityPage)
    def cves(asset_id: int, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)):
        assets.get_asset(asset_id)
        return list_priorities(asset_id=asset_id, status="all", include_archived=True, limit=limit, offset=offset)

    @router.post("/api/assets/{asset_id}/cves", status_code=201, response_model=AssessmentRecord)
    def associate(asset_id: int, body: AssessmentCreate, user=Depends(analyst), actor=Depends(mutation)):
        return assets.create_assessment(asset_id, body.model_dump(mode="json"), actor)

    @router.patch("/api/asset-assessments/{assessment_id}", response_model=AssessmentRecord)
    def assess(assessment_id: int, body: AssessmentPatch, user=Depends(analyst), actor=Depends(mutation)):
        return assets.update_assessment(assessment_id, body.model_dump(mode="json", exclude_unset=True), actor)

    @router.get("/api/assets/{asset_id}/events")
    def events(asset_id: int, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)):
        return {"items": assets.assessment_events(asset_id, limit=limit, offset=offset), "limit": limit, "offset": offset}

    @router.get("/api/priorities", response_model=PriorityPage)
    def priorities(search: str = Query("", max_length=200), environment: str = Query("", max_length=40), tag: str = Query("", max_length=32),
                   status: Literal["actionable", "all", "open", "in_progress", "remediated", "not_affected", "accepted_risk"] = "actionable",
                   exposure: Literal["", "internet", "internal", "unknown"] = "",
                   confidence: Literal["", "confirmed", "suspected"] = "", urgent_only: bool = False,
                   include_archived: bool = False, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)):
        return list_priorities(search=search, environment=environment, tag=tag, status=status, exposure=exposure,
                               confidence=confidence, urgent_only=urgent_only, include_archived=include_archived, limit=limit, offset=offset)

    def page(request, name, **context):
        return templates.TemplateResponse(request=request, name=name, context={"request": request,
            **auth_context(request), "asset_csrf_token": csrf_token(request), **context})

    @router.get("/assets", include_in_schema=False)
    def inventory_page(request: Request, user=Depends(authenticated)):
        return page(request, "assets.html", active_page="assets")

    @router.get("/assets/{asset_id}", include_in_schema=False)
    def detail_page(request: Request, asset_id: int, user=Depends(authenticated)):
        return page(request, "asset_detail.html", asset=assets.get_asset(asset_id), active_page="assets")

    @router.get("/priorities", include_in_schema=False)
    def priority_page(request: Request, user=Depends(authenticated)):
        return page(request, "priorities.html", active_page="priorities")
