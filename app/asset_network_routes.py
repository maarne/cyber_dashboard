"""Private availability/discovery endpoints, with explicit existing RBAC roles."""
import json
from typing import Literal

from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

from app import config
from app.asset_security import csrf_token, protect_mutation
from app.database import get_connection
from app.models.asset_network_schemas import (MonitorSettings, DiscoverySettings, CheckRequest, ReviewRequest, DiscoveryImportRequest,
                                            NetworkJobResponse, NetworkJobPage, MonitoringResponse)
from app.models.asset_schemas import ImportCommitRequest
from app.services import asset_service as assets, asset_network_service as network, asset_discovery_service as discovery
from app.services.asset_probe_policy import ProbePolicyError


def register_network_routes(app, templates, auth_context, authenticated, analyst, admin):
    def mutation(request: Request, user=Depends(authenticated)):
        protect_mutation(request, user)
        return {**user, 'ip_address': request.client.host if request.client else 'unknown'}

    @app.exception_handler(ProbePolicyError)
    async def policy_error(request, exc):
        return JSONResponse({'detail': str(exc)}, 422, headers={'Cache-Control': 'no-store, private'})

    @app.get('/api/assets/{asset_id}/addresses')
    def addresses(asset_id: int, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)) -> dict:
        assets.get_asset(asset_id)
        with get_connection() as conn:
            total = conn.execute('SELECT COUNT(*) FROM asset_addresses WHERE asset_id=?', (asset_id,)).fetchone()[0]
            rows = conn.execute('SELECT * FROM asset_addresses WHERE asset_id=? ORDER BY id DESC LIMIT ? OFFSET ?', (asset_id, limit, offset)).fetchall()
        return {'items': [dict(r) for r in rows], 'total': total, 'limit': limit, 'offset': offset}

    @app.get('/api/assets/{asset_id}/discovery-evidence')
    def discovery_evidence(asset_id: int, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)) -> dict:
        assets.get_asset(asset_id)
        with get_connection() as conn:
            total = conn.execute('SELECT COUNT(*) FROM asset_discovery_links WHERE asset_id=?', (asset_id,)).fetchone()[0]
            rows = conn.execute('SELECT * FROM asset_discovery_links WHERE asset_id=? ORDER BY id DESC LIMIT ? OFFSET ?', (asset_id, limit, offset)).fetchall()
        return {'items': [dict(row) for row in rows], 'total': total, 'limit': limit, 'offset': offset}

    if config.FEATURE_ASSET_MONITORING:
        @app.get('/api/asset-monitoring/capabilities')
        def monitoring_capabilities(user=Depends(authenticated)) -> dict:
            return network.capabilities_info(user['role'] == 'admin')

        @app.get('/api/asset-monitoring/status')
        def monitor_status(user=Depends(authenticated)) -> dict:
            with get_connection() as conn:
                return {'items': [{'asset_id': key, 'state': value} for key, value in network.availability_map(conn).items()]}

        @app.get('/api/assets/{asset_id}/monitoring', response_model=MonitoringResponse)
        def monitoring(asset_id: int, user=Depends(authenticated)) -> dict:
            return network.monitoring(asset_id)

        @app.put('/api/assets/{asset_id}/monitoring', response_model=MonitoringResponse)
        def configure_monitor(asset_id: int, body: MonitorSettings, user=Depends(admin), actor=Depends(mutation)) -> dict:
            return network.save_monitor(asset_id, body, actor)

        @app.post('/api/assets/{asset_id}/monitoring/check', status_code=202, response_model=NetworkJobResponse)
        def check(asset_id: int, body: CheckRequest, user=Depends(analyst), actor=Depends(mutation)) -> dict:
            return network.request_job('monitor', asset_id, body, actor)

        @app.get('/api/assets/{asset_id}/monitoring/jobs/{job_id}', response_model=NetworkJobResponse)
        def monitor_job(asset_id: int, job_id: int, user=Depends(authenticated)) -> dict:
            return network.get_job(job_id, 'monitor', asset_id)

        @app.get('/api/assets/{asset_id}/monitoring/history', response_model=NetworkJobPage)
        def monitor_history(asset_id: int, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(authenticated)) -> dict:
            assets.get_asset(asset_id)
            return network.list_jobs('monitor', asset_id, limit, offset)

        @app.get('/api/assets/{asset_id}/monitoring/export')
        def monitor_export(asset_id: int, user=Depends(admin)):
            data = {'schema_version': 1, 'monitoring': network.monitoring(asset_id), 'recent_jobs': network.list_jobs('monitor', asset_id, 100),
                    'notice': 'Bounded latest-100 monitoring export, not a restore of enabled targets/jobs.'}
            with assets.write_transaction() as conn:
                assets.audit(conn, user, 'ASSET_MONITOR_EXPORTED', asset_id)
            return JSONResponse(data, headers={'Content-Disposition': f'attachment; filename="asset-{asset_id}-monitoring-v1.json"'})

    if config.FEATURE_ASSET_DISCOVERY:
        @app.get('/api/asset-discovery/capabilities')
        def discovery_capabilities(user=Depends(analyst)) -> dict:
            return network.capabilities_info(user['role'] == 'admin')

        @app.get('/api/asset-discovery/approved-profiles')
        def approved_profiles(user=Depends(analyst)) -> dict:
            rows = network.profiles()['items']
            return {'items': [{'id': r['id'], 'name': r['settings']['name'], 'generation': r['generation'],
                               'enabled': r['enabled'], 'next_due': r['next_due']} for r in rows]}

        @app.get('/api/asset-discovery/profiles')
        def profiles(user=Depends(admin)) -> dict:
            return network.profiles()

        @app.post('/api/asset-discovery/profiles', status_code=201)
        def create_profile(body: DiscoverySettings, user=Depends(admin), actor=Depends(mutation)) -> dict:
            return network.save_profile(None, body, actor)

        @app.get('/api/asset-discovery/profiles/{profile_id}')
        def profile(profile_id: int, user=Depends(admin)) -> dict:
            return network.profile(profile_id)

        @app.patch('/api/asset-discovery/profiles/{profile_id}')
        def update_profile(profile_id: int, body: DiscoverySettings, user=Depends(admin), actor=Depends(mutation)) -> dict:
            return network.save_profile(profile_id, body, actor)

        @app.post('/api/asset-discovery/profiles/{profile_id}/runs', status_code=202, response_model=NetworkJobResponse)
        def run(profile_id: int, body: CheckRequest, user=Depends(analyst), actor=Depends(mutation)) -> dict:
            return network.request_job('discovery', profile_id, body, actor)

        @app.get('/api/asset-discovery/runs', response_model=NetworkJobPage)
        def runs(profile_id: int | None = None, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(analyst)) -> dict:
            return network.list_jobs('discovery', profile_id, limit, offset)

        @app.get('/api/asset-discovery/runs/{job_id}', response_model=NetworkJobResponse)
        def run_detail(job_id: int, user=Depends(analyst)) -> dict:
            return network.get_job(job_id, 'discovery')

        @app.post('/api/asset-discovery/runs/{job_id}/cancel', response_model=NetworkJobResponse)
        def cancel_run(job_id: int, user=Depends(analyst), actor=Depends(mutation)) -> dict:
            return network.cancel_job(job_id, actor)

        @app.get('/api/asset-discovery/candidates')
        def candidates(search: str = Query('', max_length=200), profile_id: int | None = None, network: str = Query('', max_length=64),
                       review: Literal['new', 'all', 'ignored', 'imported'] = 'new', limit: int = Query(50, ge=1, le=100),
                       offset: int = Query(0, ge=0), user=Depends(analyst)) -> dict:
            return discovery.candidates(search=search, profile_id=profile_id, network=network, review=review, limit=limit, offset=offset)

        @app.post('/api/asset-discovery/candidates/{candidate_id}/review')
        def review(candidate_id: int, body: ReviewRequest, user=Depends(admin), actor=Depends(mutation)) -> dict:
            return discovery.review_candidate(candidate_id, body, actor)

        @app.post('/api/asset-discovery/import/preview')
        def preview(body: DiscoveryImportRequest, user=Depends(admin), actor=Depends(mutation)) -> dict:
            return discovery.preview_import(body, actor)

        @app.post('/api/asset-discovery/import/commit')
        def commit(body: ImportCommitRequest, user=Depends(admin), actor=Depends(mutation)) -> dict:
            return discovery.commit_import(body.preview_token, actor)

        @app.get('/asset-discovery', include_in_schema=False)
        def discovery_page(request: Request, user=Depends(analyst)):
            return templates.TemplateResponse(request=request, name='asset_discovery.html', context={
                'request': request, **auth_context(request), 'asset_csrf_token': csrf_token(request), 'active_page': 'discovery'})
