"""Disposable two-human-account rule review demonstration; no scans or deployments."""
from scratch import test_support
import os
os.environ.update(FEATURE_RULE_LIFECYCLE='true',FEATURE_CASE_MANAGEMENT='false',FEATURE_ASSET_PRIORITIZATION='false',
                  FEATURE_ASSET_MONITORING='false',FEATURE_ASSET_DISCOVERY='false',PUBLIC_BASE_URL='http://localhost:8768')
from app.database import initialize_database
from app.services import auth_service as auth
initialize_database()
auth.complete_initial_setup('rule_author','Preview-Only#2026C')
auth.create_user('rule_reviewer','Preview-Only#2026C','admin')

if __name__=='__main__':
    import uvicorn
    uvicorn.run('app.main:app',host='127.0.0.1',port=8768)
