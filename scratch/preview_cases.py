"""Disposable local-only case UI; all network enrichment explicitly forbidden."""
from scratch import test_support
import os
os.environ.update(FEATURE_CASE_MANAGEMENT='true', FEATURE_ASSET_PRIORITIZATION='true',
                  FEATURE_ASSET_MONITORING='false', FEATURE_ASSET_DISCOVERY='false', PUBLIC_BASE_URL='http://localhost:8767')
from app.database import initialize_database
from app.services import auth_service as auth, ioc_service as ioc


def forbidden(*args, **kwargs):
    raise RuntimeError('No DNS or network enrichment is available in this isolated preview.')


for method in ('enrich_ip', 'enrich_domain', 'enrich_url'):
    setattr(ioc, method, forbidden)
initialize_database()
auth.complete_initial_setup('case_preview', 'Preview-Only#2026B')
auth.create_user('case_analyst', 'Preview-Only#2026B', 'analyst')

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('app.main:app', host='127.0.0.1', port=8767)
