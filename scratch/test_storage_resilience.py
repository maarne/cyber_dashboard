"""Storage operator workflows use synthetic files only, never the workspace DB."""
from scratch import test_support
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


class StorageResilienceTests(unittest.TestCase):
    def setUp(self):
        # A private home-directory sandbox exercises durable-mode restrictions;
        # it is not inside /tmp and is removed only by its owning TemporaryDirectory.
        parent=Path.home()/'.local/share'
        parent.mkdir(parents=True,exist_ok=True)
        self.sandbox=tempfile.TemporaryDirectory(prefix='cyberdash-storage-test-',dir=parent)
        self.root=Path(self.sandbox.name)
        self.data=self.root/'data'
        self.env={k:v for k,v in os.environ.items() if not (k.startswith(('FEATURE_','ASSET_','DB_')) or k in
            ('DATABASE_PATH','DATABASE_URL','DATABASE_URL_FILE','APP_DATA_DIR','JWT_SECRET_KEY','JWT_SECRET_KEY_FILE',
             'ALLOW_EPHEMERAL_STORAGE','EXPECTED_DATABASE_ID','ENV','PUBLIC_BASE_URL'))}

    def tearDown(self): self.sandbox.cleanup()

    def command(self,*arguments,expected=0,env=None):
        r=subprocess.run([sys.executable,'-B','-m','scripts.configure_storage',*arguments],
            env={**self.env,**(env or {})},capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
        return json.loads([line for line in r.stdout.splitlines() if line.startswith('{')][-1])

    def initialize(self,**kwargs):
        return self.command('init','--data-dir',str(self.data),'--confirm-new',**kwargs)

    def manifest(self): return json.loads((self.data/'installation.json').read_text())

    def code(self,program,extra=None,expected=0):
        r=subprocess.run([sys.executable,'-B','-c',program],env={**self.env,'APP_DATA_DIR':str(self.data),**(extra or {})},
            capture_output=True,text=True,timeout=40)
        self.assertEqual(r.returncode,expected,r.stdout+r.stderr)
        return r

    def http_state(self):
        r=self.code('''import json
from fastapi.testclient import TestClient
from app.main import app
with TestClient(app,raise_server_exceptions=False) as c:
    ready=c.get('/api/ready')
    print(json.dumps({'health':c.get('/api/health').status_code,'ready':ready.status_code,'body':ready.json(),
        'setup':c.get('/setup').status_code,'register':c.post('/api/setup',json={'username':'intruder','password':'Synthetic-Only#2026'}).status_code}))
''')
        return json.loads([line for line in r.stdout.splitlines() if line.startswith('{')][-1])

    def test_explicit_init_persists_key_identity_permissions_and_settings(self):
        result=self.initialize(env={'FEATURE_CASE_MANAGEMENT':'true','ASSET_PROBE_ALLOWED_CIDRS':''})
        self.assertEqual(result['status'],'configured')
        profile=self.manifest(); key=(self.data/'signing.key').read_text().strip()
        self.assertNotIn(key,json.dumps(profile)); self.assertNotIn(key,json.dumps(result))
        self.assertEqual(profile['settings']['ASSET_PROBE_ALLOWED_CIDRS'],'')
        for path in ('installation.json','signing.key','cyber_dashboard.db'):
            self.assertEqual((self.data/path).stat().st_mode & 0o777,0o600)
        self.assertEqual(self.data.stat().st_mode & 0o777,0o700)
        program="from app.config import JWT_SECRET_KEY,FEATURE_CASE_MANAGEMENT,ASSET_PROBE_ALLOWED_CIDRS; from app.database import get_connection; assert FEATURE_CASE_MANAGEMENT and ASSET_PROBE_ALLOWED_CIDRS==''; import hashlib; print(hashlib.sha256(JWT_SECRET_KEY.encode()).hexdigest())"
        fingerprint=hashlib.sha256(key.encode()).hexdigest()
        self.assertEqual(self.code(program).stdout.strip(),fingerprint)
        self.assertEqual(self.code(program).stdout.strip(),fingerprint)
        self.assertEqual(self.command('status','--data-dir',str(self.data))['database_id'],profile['database_id'])

    def test_init_requires_consent_and_never_overwrites(self):
        self.assertEqual(self.command('init','--data-dir',str(self.data),expected=1)['code'],'explicit_initialization_confirmation_required')
        self.initialize()
        before=(self.data/'cyber_dashboard.db').read_bytes()
        self.command('init','--data-dir',str(self.data),'--confirm-new',expected=1)
        self.assertEqual((self.data/'cyber_dashboard.db').read_bytes(),before)

    def test_missing_database_stays_missing_and_setup_stays_closed(self):
        self.initialize(); source=self.data/'cyber_dashboard.db'; source.rename(self.data/'held.db')
        state=self.http_state()
        self.assertEqual(state['health'],200); self.assertEqual(state['ready'],503)
        self.assertEqual(state['body']['code'],'database_missing')
        self.assertEqual(state['setup'],503); self.assertEqual(state['register'],503)
        self.assertFalse(source.exists())

    def test_wrong_or_empty_database_is_not_repaired_or_reseeded(self):
        self.initialize(); source=self.data/'cyber_dashboard.db'; source.rename(self.data/'held.db')
        source.touch(mode=0o600)
        state=self.http_state()
        self.assertEqual(state['body']['code'],'database_identity_mismatch')
        self.assertEqual(source.stat().st_size,0)

    def test_missing_manifest_does_not_adopt_existing_database(self):
        self.initialize(); source=self.data/'cyber_dashboard.db'
        key=(self.data/'signing.key').read_text().strip()
        before=source.read_bytes(); (self.data/'installation.json').unlink()
        program="from app.database import get_connection; from app.storage.local import StorageError\ntry: get_connection()\nexcept StorageError as e: print(e.code)"
        result=self.code(program,{'JWT_SECRET_KEY':key,'DATABASE_PATH':str(source)})
        self.assertIn('storage_configuration_required',result.stdout)
        self.assertEqual(source.read_bytes(),before)

    def test_deleted_admin_is_recovery_not_registration(self):
        self.initialize()
        self.code("from app.services.auth_service import complete_initial_setup; complete_initial_setup('owner','Synthetic-Only#2026')")
        with sqlite3.connect(self.data/'cyber_dashboard.db') as conn: conn.execute('DELETE FROM users')
        state=self.http_state()
        self.assertEqual(state['body']['code'],'administrator_recovery_required')
        self.assertEqual(state['register'],503)

    def test_key_file_missing_conflict_and_empty_env_never_rotate_key(self):
        self.initialize(); key=self.data/'signing.key'; original=key.read_bytes()
        key.rename(self.data/'held.key')
        result=self.code('import app.config',expected=1)
        self.assertNotIn(original.decode().strip(),result.stderr); self.assertFalse(key.exists())
        key.write_bytes(original); key.chmod(0o600)
        self.assertIn('not both',self.code('import app.config',{'JWT_SECRET_KEY':'x'*40,'JWT_SECRET_KEY_FILE':str(key)},expected=1).stderr)
        self.code('import app.config',{'JWT_SECRET_KEY':''},expected=1)
        self.assertEqual(key.read_bytes(),original)

    def test_ephemeral_path_requires_explicit_disposable_opt_in(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as td:
            target=str(Path(td)/'data')
            self.assertEqual(self.command('init','--data-dir',target,'--confirm-new',expected=1)['code'],'ephemeral_storage_refused')
            result=self.command('init','--data-dir',target,'--confirm-new','--allow-ephemeral-storage')
            self.assertTrue(result['disposable'])

    def test_external_config_is_rejected_not_silently_sqlite(self):
        self.initialize()
        result=self.code('import app.config',{'DATABASE_URL':'postgresql://hidden:private@db/app'},expected=1)
        self.assertIn('external_database_not_supported_yet',result.stderr)
        self.assertNotIn('hidden:private',result.stderr)

    def test_concurrent_initializers_produce_one_identity(self):
        command=[sys.executable,'-B','-m','scripts.configure_storage','init','--data-dir',str(self.data),'--confirm-new']
        def run(_): return subprocess.run(command,env=self.env,capture_output=True,text=True,timeout=40).returncode
        with ThreadPoolExecutor(2) as pool: self.assertEqual(sorted(pool.map(run,range(2))),[0,1])
        self.assertEqual(self.command('status','--data-dir',str(self.data))['status'],'ready')

    def test_adoption_makes_backup_and_requires_existing_signing_key(self):
        self.initialize(); source=self.root/'legacy.db'
        with sqlite3.connect(self.data/'cyber_dashboard.db') as a, sqlite3.connect(source) as b: a.backup(b)
        with sqlite3.connect(source) as conn:
            conn.execute('DROP TABLE installation_metadata')
            conn.execute("INSERT INTO users(username,password_hash,role,is_primary) VALUES ('existing','inert-fixture','admin',1)")
            conn.execute('DELETE FROM detection_rules WHERE id=(SELECT MIN(id) FROM detection_rules)')
            before_rules=conn.execute('SELECT COUNT(*) FROM detection_rules').fetchone()[0]
        destination=self.root/'adopted'
        before=source.read_bytes()
        with sqlite3.connect(source) as conn: before_sql=list(conn.iterdump())
        self.assertEqual(self.command('adopt','--data-dir',str(destination),'--database',str(source),'--confirm-adopt',expected=1)['code'],'original_signing_key_required')
        self.assertEqual(source.read_bytes(),before)
        key=secrets.token_hex(32)
        result=self.command('adopt','--data-dir',str(destination),'--database',str(source),'--confirm-adopt',env={'JWT_SECRET_KEY':key})
        self.assertTrue(result['backup_created'])
        backups=list((destination/'backups').glob('*.db')); self.assertEqual(len(backups),1)
        with sqlite3.connect(backups[0]) as conn: self.assertEqual(list(conn.iterdump()),before_sql)
        with sqlite3.connect(source) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE username='existing'").fetchone()[0],1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM detection_rules').fetchone()[0],before_rules)
        self.code("from app.database import initialize_database,get_connection; initialize_database();\nwith get_connection() as c: assert c.execute('SELECT COUNT(*) FROM detection_rules').fetchone()[0]==%d"%before_rules,
                  {'APP_DATA_DIR':str(destination),'JWT_SECRET_KEY':key})

    def test_unknown_database_and_symlink_are_refused(self):
        source=self.root/'other.db'
        with sqlite3.connect(source) as conn: conn.execute('CREATE TABLE unrelated (value TEXT)')
        before=source.read_bytes()
        self.assertEqual(self.command('adopt','--data-dir',str(self.data),'--database',str(source),'--confirm-adopt',expected=1)['code'],'unknown_database_schema')
        self.assertEqual(source.read_bytes(),before)
        link=self.root/'symlink'; link.symlink_to(source)
        self.assertEqual(self.command('inspect','--database',str(link),expected=1)['code'],'unsafe_storage_path')

    def test_interrupted_finalization_resumes_only_matching_existing_db(self):
        self.initialize(); profile=self.manifest(); profile['state']='initializing'
        (self.data/'installation.json').write_text(json.dumps(profile))
        self.assertEqual(self.http_state()['body']['code'],'initialization_incomplete')
        self.command('resume','--data-dir',str(self.data),'--confirm-resume')
        self.assertEqual(self.manifest()['state'],'ready')
        profile['state']='initializing'; (self.data/'installation.json').write_text(json.dumps(profile))
        (self.data/'cyber_dashboard.db').unlink()
        self.assertEqual(self.command('resume','--data-dir',str(self.data),'--confirm-resume',expected=1)['code'],'database_missing')
        self.assertFalse((self.data/'cyber_dashboard.db').exists())

    def test_private_backup_bundle_restores_in_isolated_location(self):
        self.initialize()
        self.code("from app.services.auth_service import complete_initial_setup; complete_initial_setup('owner','Synthetic-Only#2026')")
        backup_root=self.root/'independent-backups'
        program="from scripts.backup_installation import backup_installation; from pathlib import Path; print(backup_installation(Path(%r),Path(%r),True))"%(str(self.data),str(backup_root))
        destination=Path(self.code(program).stdout.strip())
        record=json.loads((destination/'backup.json').read_text())
        self.assertTrue(record['managed_signing_key_included'])
        self.assertEqual((destination/'signing.key').read_bytes(),(self.data/'signing.key').read_bytes())
        adopted=self.root/'restored-installation'
        restored_db=self.root/'restored.db'; restored_db.write_bytes((destination/'dashboard.db').read_bytes())
        result=self.command('adopt','--data-dir',str(adopted),'--database',str(restored_db),'--confirm-adopt',env={'JWT_SECRET_KEY_FILE':str(destination/'signing.key')})
        self.assertEqual(result['database_id'],self.manifest()['database_id'])
        restored=self.code("from app.services.auth_service import get_user_by_username,verify_password; from app.services.audit_service import verify_audit_log_integrity; assert verify_password('Synthetic-Only#2026',get_user_by_username('owner')['password_hash']); assert verify_audit_log_integrity()['is_valid']; print('restore_verified')",{'APP_DATA_DIR':str(adopted)})
        self.assertIn('restore_verified',restored.stdout)

    def test_missing_table_does_not_silently_reseed_it(self):
        self.initialize()
        source=self.data/'cyber_dashboard.db'
        with sqlite3.connect(source) as conn: conn.execute('DROP TABLE rss_feeds')
        self.assertEqual(self.http_state()['body']['code'],'schema_incomplete')
        with sqlite3.connect(source) as conn:
            self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='rss_feeds'").fetchone())

    def test_manifest_permissions_and_symlink_are_rejected(self):
        self.initialize(); path=self.data/'installation.json'
        path.chmod(0o644)
        self.assertIn('configuration_permissions',self.code('import app.config',expected=1).stderr)
        path.chmod(0o600); path.rename(self.data/'held.json'); path.symlink_to(self.data/'held.json')
        self.code('import app.config',expected=1)

    def test_storage_disappearing_after_start_never_reopens_setup(self):
        self.initialize()
        r=self.code('''from fastapi.testclient import TestClient
from app.main import app
from app.config import DATABASE_PATH
with TestClient(app) as c:
    assert c.get('/api/ready').status_code==200
    DATABASE_PATH.rename(DATABASE_PATH.with_name('held.db'))
    assert c.get('/api/ready').status_code==503
    assert c.get('/setup').status_code==503
    assert not DATABASE_PATH.exists()
print('runtime_missing_blocked')
''')
        self.assertIn('runtime_missing_blocked',r.stdout)

    def test_corrupt_sqlite_retains_liveness_without_creating_replacement(self):
        self.initialize(); source=self.data/'cyber_dashboard.db'; source.write_bytes(b'invalid SQLite fixture')
        before=source.read_bytes(); state=self.http_state()
        self.assertEqual(state['health'],200); self.assertEqual(state['ready'],503)
        self.assertEqual(source.read_bytes(),before)

    def test_retired_admin_deletion_script_has_no_database_side_effects(self):
        self.initialize(); source=self.data/'cyber_dashboard.db'; before=source.read_bytes()
        r=subprocess.run([sys.executable,'-B','reset_admin_setup.py'],env=self.env,capture_output=True,text=True)
        self.assertNotEqual(r.returncode,0); self.assertIn('no accounts were deleted',r.stderr)
        self.assertEqual(source.read_bytes(),before)

    def test_failed_backup_never_replaces_last_completed_bundle(self):
        self.initialize(); output=self.root/'independent'
        program="from scripts.backup_installation import backup_installation; from pathlib import Path; print(backup_installation(Path(%r),Path(%r)))"%(str(self.data),str(output))
        destination=Path(self.code(program).stdout.strip()); before=(destination/'dashboard.db').read_bytes()
        with sqlite3.connect(self.data/'cyber_dashboard.db') as conn: conn.execute('DROP TABLE rss_feeds')
        self.code(program,expected=1)
        self.assertEqual((destination/'dashboard.db').read_bytes(),before)
        self.assertEqual(len(list(output.glob('*/backup.json'))),1)


if __name__=='__main__': unittest.main(verbosity=2)
