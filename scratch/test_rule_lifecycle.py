"""Isolated lifecycle acceptance fixtures. Only source parsing/compilation, never scanning."""
from scratch import test_support
import json
import os
import re
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

os.environ['FEATURE_RULE_LIFECYCLE']='true'
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import config
from app.database import initialize_database,get_connection
from app.main import app
from app.models.rule_schemas import RuleSnapshot,RuleAction,RuleReview
from app.rule_migrations import manage_existing,FIELDS
from app.services import rule_lifecycle_service as rules,rule_validation_service as validation,rule_service as legacy,auth_service as auth
from app.services.audit_service import verify_audit_log_integrity
from app.services.api_token_service import generate_api_token,get_api_endpoints_catalog

SIGMA='''title: Benign process fixture
id: e7ab3af1-e7d5-4fa9-9539-193727781fe1
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: fixture.exe
  condition: selection
level: high
'''
YARA='rule Benign_Fixture { strings: $a = "fixture" condition: $a }\n'


class RuleLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        cls.seeded=legacy.get_all_detection_rules()
        password=auth.generate_secure_random_password(18)
        auth.complete_initial_setup('owner',password)
        for name,role in (('reviewer','admin'),('analyst','analyst'),('viewer','viewer')): auth.create_user(name,password,role)
        cls.actors={name:{'username':name,'role':auth.get_user_by_username(name)['role'],'user_id':auth.get_user_by_username(name)['id']} for name in ('owner','reviewer','analyst','viewer')}
        cls.headers={name:{'Authorization':'Bearer '+auth.create_access_token(name)} for name in cls.actors}

    def setUp(self):
        test_support.assert_test_database(); self.client=TestClient(app)
        with get_connection() as conn:
            conn.execute('UPDATE detection_rules SET working_revision_id=NULL,published_revision_id=NULL')
            conn.execute('UPDATE rule_revisions SET submitted_validation_id=NULL,parent_revision_id=NULL')
            for table in ('rule_validation_claims','rule_reviews','rule_lifecycle_events','rule_validation_runs','rule_revisions','detection_rules','audit_logs'):
                conn.execute(f'DELETE FROM {table}')
            self.legacy_id=conn.execute("INSERT INTO detection_rules(title,rule_type,code_content,severity) VALUES ('Legacy fixture','Sigma','title: unvalidated','HIGH')").lastrowid
            manage_existing(conn)

    def tearDown(self): self.client.close()

    def request(self,method,path,body=None,actor='owner',expected=200):
        r=self.client.request(method,path,headers=self.headers[actor],**({'json':body} if body is not None else {}))
        self.assertEqual(r.status_code,expected,r.text); self.assertIn('no-store',r.headers['cache-control'])
        return r.json()

    def draft(self,actor='owner',**fields):
        return self.request('POST','/api/rule-lifecycle/rules',{'title':'PRIVATE draft needle','rule_type':'Sigma','code_content':SIGMA,**fields},actor,201)

    def action(self,r,name,actor='owner',expected=200,**fields):
        return self.request('POST',f"/api/detection-rules/{r['id']}/revisions/{r['working']['id']}/{name}",{'expected_version':r['row_version'],**fields},actor,expected)

    def approved(self):
        r=self.draft(); self.action(r,'validate'); r=self.action(r,'submit')
        return self.action(r,'review','reviewer',decision='approved',reason='Independent fixture structure review')

    def test_migration_legacy_exact_unreviewed_and_seeding_preserves_identity(self):
        self.assertEqual(len(self.seeded),15)
        self.assertTrue(all(r['lifecycle_state']=='legacy_unreviewed' for r in self.seeded))
        before=legacy.get_rule_by_id(self.legacy_id)
        initialize_database(); legacy.seed_default_detection_rules()
        after=legacy.get_rule_by_id(self.legacy_id)
        self.assertEqual(before,after); self.assertEqual(len(legacy.get_all_detection_rules()),1)
        self.assertEqual(after['code_content'],'title: unvalidated')
        with get_connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0],4)
            self.assertFalse(conn.execute('PRAGMA foreign_key_check').fetchall())

    def test_sigma_and_yara_actual_validators_and_strict_invalid_fixtures(self):
        for typ,source in (('Sigma',SIGMA),('YARA',YARA)):
            report=validation.run_validator({'rule_type':typ,'code_content':source})
            self.assertEqual(report['status'],'valid',report)
            self.assertIn('not proof',report['warnings'][0])
        bad=[('Sigma',SIGMA.replace('e7ab3af1-e7d5-4fa9-9539-193727781fe1','not-uuid')),
             ('Sigma',SIGMA.replace('condition: selection','condition: missing')),
             ('Sigma',SIGMA.replace('status: experimental','status: production')),
             ('Sigma','!!python/object/apply:os.system ["echo forbidden"]'),('Sigma','a: &a [*a]'),
             ('Sigma',SIGMA+'\n---\ntitle: second'),('Sigma',SIGMA+'\nlevel: low'),
             ('Sigma','nested: '+ '['*25+'1'+']'*25),('YARA','include "/etc/passwd"\n'+YARA),
             ('YARA','import "pe"\n'+YARA),('YARA','rule Invalid { condition: not_defined }')]
        for typ,source in bad:
            with self.subTest(source=source[:50]): self.assertEqual(validation.run_validator({'rule_type':typ,'code_content':source})['status'],'invalid')

    def test_source_only_yara_strings_are_not_include_directives(self):
        source='rule Fixture { strings: $a = "include import" condition: $a }'
        self.assertEqual(validation.run_validator({'rule_type':'YARA','code_content':source})['status'],'valid')

    def test_drafts_private_across_detail_html_search_download_and_hidden_data(self):
        r=self.draft(); rid=r['id']
        for path in (f'/api/detection-rules/{rid}',f'/api/detection-rules/{rid}/download'):
            self.request('GET',path,actor='viewer',expected=404)
        page=self.client.get('/rules').text
        self.assertNotIn('PRIVATE draft needle',page); self.assertNotIn('fixture.exe',page)
        self.assertEqual(self.request('GET','/api/detection-rules?search=PRIVATE',actor='viewer'),[])
        self.assertEqual(len(self.request('GET','/api/detection-rules',actor='viewer')),1)
        for path in ('/api/rule-lifecycle/rules',f'/api/detection-rules/{rid}/working',f'/api/detection-rules/{rid}/revisions',f'/rule-workbench/{rid}'):
            self.request('GET',path,actor='viewer',expected=403)
            self.assertEqual(self.client.get(path).status_code,401)

    def test_full_review_publication_keeps_old_public_while_new_draft_exists(self):
        r=self.approved(); r=self.action(r,'publish','reviewer')
        public=self.request('GET',f"/api/detection-rules/{r['id']}",actor='viewer')
        old_revision=public['revision_id']; self.assertEqual(public['lifecycle_state'],'published')
        snapshot=r['working']['snapshot']
        new=self.request('POST',f"/api/detection-rules/{r['id']}/revisions",{**snapshot,'title':'PRIVATE successor','expected_version':r['row_version'],'expected_parent_revision_id':r['working']['id']},expected=201)
        self.assertIsNone(new['working']['validation']); self.assertEqual(new['working']['reviews'],[])
        self.assertEqual(self.request('GET',f"/api/detection-rules/{r['id']}",actor='viewer')['revision_id'],old_revision)
        self.assertNotIn('PRIVATE successor',self.client.get('/rules').text)
        download=self.client.get(f"/api/detection-rules/{r['id']}/download")
        self.assertEqual(download.status_code,200); self.assertEqual(download.headers['x-rule-revision'],str(old_revision))
        self.assertNotIn('PRIVATE successor',download.text)
        self.assertTrue(verify_audit_log_integrity()['is_valid'])

    def test_self_review_machine_review_publish_and_missing_validation_rejected(self):
        r=self.draft(); self.action(r,'submit',expected=409)
        self.action(r,'validate'); r=self.action(r,'submit')
        self.action(r,'review',expected=403,decision='approved',reason='Self review forbidden')
        token,metadata=generate_api_token('machine','admin','owner')
        for action,extra in (('review',{'decision':'approved','reason':'Service is not human'}),('publish',{})):
            response=self.client.post(f"/api/detection-rules/{r['id']}/revisions/{r['working']['id']}/{action}",json={'expected_version':r['row_version'],**extra},headers={'X-API-Key':token})
            self.assertEqual(response.status_code,403,response.text)
        r=self.action(r,'review','reviewer',decision='rejected',reason='Needs log fixtures')
        self.assertEqual(r['working']['state'],'rejected'); self.action(r,'publish','reviewer',expected=409)

    def test_withdraw_rollback_immutability_and_stale_parent(self):
        r=self.draft(); original=r['working']; self.action(r,'validate'); r=self.action(r,'submit')
        self.request('POST',f"/api/detection-rules/{r['id']}/revisions",{**original['snapshot'],'expected_version':r['row_version'],'expected_parent_revision_id':original['id']},expected=409)
        r=self.action(r,'withdraw'); self.assertNotEqual(r['working']['id'],original['id']); self.assertIsNone(r['working']['validation'])
        self.assertEqual(self.request('GET',f"/api/detection-rules/{r['id']}/revisions/{original['id']}")['state'],'withdrawn')
        r=self.request('POST',f"/api/detection-rules/{r['id']}/rollback",{'expected_version':r['row_version'],'source_revision_id':original['id'],'reason':'Restore previous content'})
        self.assertEqual(r['working']['sha256'],original['sha256']); self.assertEqual(r['working']['state'],'draft')
        self.assertEqual(r['working']['reviews'],[]); self.action(r,'publish','reviewer',expected=409)
        self.request('POST',f"/api/detection-rules/{r['id']}/revisions",{**original['snapshot'],'expected_version':r['row_version'],'expected_parent_revision_id':original['id']},expected=409)

    def test_validation_policy_changes_tampering_and_reviewer_demotion_block_publish(self):
        r=self.approved()
        with patch.object(validation,'validator_version',return_value='new-policy'):
            self.action(r,'publish','reviewer',expected=409)
        with get_connection() as conn: conn.execute("UPDATE users SET role='analyst' WHERE username='reviewer'")
        try: self.action(r,'publish',expected=409)
        finally:
            with get_connection() as conn: conn.execute("UPDATE users SET role='admin' WHERE username='reviewer'")
        with get_connection() as conn: conn.execute("UPDATE rule_revisions SET snapshot_json='{}' WHERE id=?",(r['working']['id'],))
        self.action(r,'publish','reviewer',expected=409)

    def test_concurrent_publication_and_atomic_audit_failure(self):
        r=self.approved(); body=RuleAction(expected_version=r['row_version'])
        with patch('app.services.rule_lifecycle_service.log_audit_event',side_effect=RuntimeError('Audit unavailable')):
            with self.assertRaises(RuntimeError): rules.publish(r['id'],r['working']['id'],body,self.actors['reviewer'])
        self.assertIsNone(legacy.get_rule_by_id(r['id']))
        def publish(_):
            try: rules.publish(r['id'],r['working']['id'],body,self.actors['reviewer']); return 200
            except HTTPException as exc: return exc.status_code
        with ThreadPoolExecutor(2) as pool: self.assertEqual(sorted(pool.map(publish,(1,2))),[200,409])

    def test_shared_capacity_busy_claim_cleanup_and_validation_storage_limit(self):
        r=self.draft(); other=self.draft(title='Other')
        with get_connection() as conn:
            conn.execute('INSERT INTO rule_validation_claims VALUES (1,?,?,?)',(r['working']['id'],'one',time.time()+30))
            conn.execute('INSERT INTO rule_validation_claims VALUES (2,?,?,?)',(other['working']['id'],'two',time.time()+30))
        third=self.draft(title='Third'); self.action(third,'validate',expected=503)
        self.action(r,'validate',expected=409)
        with get_connection() as conn: conn.execute('UPDATE rule_validation_claims SET expires_at=0')
        self.assertEqual(self.action(r,'validate')['report']['status'],'valid')
        with patch.dict(rules.LIMITS,validation_runs_per_revision=1): self.action(r,'validate',expected=409)

    def test_cookie_csrf_limits_archive_and_hard_delete_retired(self):
        self.client.cookies.set('access_token',self.headers['owner']['Authorization'][7:])
        page=self.client.get('/rule-workbench').text
        token=re.search(r'name="rule-csrf-token" content="([a-f0-9]+)"',page)[1]
        body={'title':'Cookie draft','code_content':YARA,'rule_type':'YARA'}
        self.assertEqual(self.client.post('/api/rule-lifecycle/rules',json=body).status_code,403)
        response=self.client.post('/api/rule-lifecycle/rules',json=body,headers={'Origin':'http://testserver','X-CSRF-Token':token})
        self.assertEqual(response.status_code,201,response.text)
        r=response.json()
        self.request('DELETE',f"/api/detection-rules/{r['id']}",expected=409)
        self.request('PUT',f"/api/detection-rules/{r['id']}",body,expected=409)
        r=self.request('POST',f"/api/detection-rules/{r['id']}/archive",{'expected_version':r['row_version'],'archived':True,'reason':'Retain history'})
        self.assertTrue(r['is_archived']); self.action(r,'validate',expected=409)
        with patch.dict(rules.LIMITS,revisions_per_rule=1):
            other=self.draft()
            self.request('POST',f"/api/detection-rules/{other['id']}/revisions",{**other['working']['snapshot'],'expected_version':1,'expected_parent_revision_id':other['working']['id']},expected=409)
        self.request('POST','/api/rule-lifecycle/rules',{'title':'Large','code_content':'é'*110000},expected=422)

    def test_feature_disable_latch_never_reactivates_mutable_crud(self):
        r=self.draft()
        code=f'''from app.main import app
from fastapi.testclient import TestClient
from app.services.auth_service import create_access_token
c=TestClient(app)
h={{'Authorization':'Bearer '+create_access_token('owner')}}
assert c.get('/rule-workbench',headers=h).status_code==404
assert c.get('/api/rule-lifecycle/rules',headers=h).status_code==404
assert c.get('/api/detection-rules/{r['id']}',headers=h).status_code==404
assert c.post('/api/detection-rules',headers=h,json={{'title':'Bypass','code_content':'test'}}).status_code==409
assert c.delete('/api/detection-rules/{self.legacy_id}',headers=h).status_code==409
assert 'legacy_unreviewed' in c.get('/rules').text or 'Legacy' in c.get('/rules').text
'''
        env={**os.environ,'FEATURE_RULE_LIFECYCLE':'false'}
        result=subprocess.run([sys.executable,'-B','-c',code],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_missing_dependency_and_worker_timeout_are_not_valid(self):
        request={'snapshot':{'rule_type':'YARA','code_content':YARA},'validator_version':validation.validator_version('YARA')}
        result=subprocess.run([sys.executable,'-S','-B','app/rule_validator_process.py'],input=json.dumps(request),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['reason'],'dependency_unavailable')
        original=validation.subprocess.Popen; processes=[]
        def slow(command,**kwargs):
            self.assertNotIn('JWT_SECRET_KEY',kwargs['env']); self.assertTrue(kwargs['start_new_session'])
            p=original([sys.executable,'-c','import sys,time; sys.stdin.buffer.read(); time.sleep(20)'],**kwargs)
            processes.append(p); return p
        with patch.object(validation.subprocess,'Popen',side_effect=slow):
            report=validation.run_validator(request['snapshot'])
        self.assertEqual(report['status'],'error'); self.assertEqual(report['reason'],'timeout'); self.assertIsNotNone(processes[0].returncode)

    def test_history_diff_export_and_public_yara_download_compile(self):
        r=self.draft(rule_type='YARA',code_content=YARA)
        self.action(r,'validate'); r=self.action(r,'submit'); r=self.action(r,'review','reviewer',decision='approved',reason='Benign compile fixture')
        r=self.action(r,'publish','reviewer')
        source=self.client.get(f"/api/detection-rules/{r['id']}/download").text
        self.assertTrue(source.startswith('//')); self.assertEqual(validation.run_validator({'rule_type':'YARA','code_content':source})['status'],'valid')
        first=r['working']['id']
        r=self.request('POST',f"/api/detection-rules/{r['id']}/revisions",{**r['working']['snapshot'],'code_content':YARA.replace('fixture','different'),'expected_version':r['row_version'],'expected_parent_revision_id':first},expected=201)
        diff=self.request('GET',f"/api/detection-rules/{r['id']}/diff?older={first}&newer={r['working']['id']}")
        self.assertIn('-rule Benign_Fixture',diff['diff'])
        report=self.request('GET',f"/api/detection-rules/{r['id']}/revisions/export")
        self.assertEqual(len(report['revisions']),2); self.assertEqual(report['schema_version'],1)

    def test_explorer_permissions(self):
        catalog={(r['path'],r['method']):r['auth_required'] for r in get_api_endpoints_catalog()}
        self.assertEqual(catalog[('/api/rule-lifecycle/rules','POST')],'Analyst / Admin')
        self.assertEqual(catalog[('/api/detection-rules/{rule_id}/revisions/{revision_id}/publish','POST')],'Admin')

    def test_migration_from_version_three_is_exact_and_atomic(self):
        from app import database
        from app.rule_migrations import apply_rule_migration
        target=Path(test_support._sandbox.name)/'rule-upgrade.db'
        with patch.object(database,'DATABASE_PATH',target):
            with patch.object(config,'FEATURE_RULE_LIFECYCLE',False), patch('app.rule_migrations.apply_rule_migration'):
                initialize_database()
            with get_connection() as conn:
                conn.execute("UPDATE detection_rules SET description=NULL,code_content=code_content||char(10)||'  ' WHERE id=1")
                before=[dict(row) for row in conn.execute('SELECT * FROM detection_rules ORDER BY id')]
            with self.assertRaises(RuntimeError):
                with get_connection() as conn:
                    conn.execute('BEGIN IMMEDIATE'); apply_rule_migration(conn); raise RuntimeError('rollback fixture')
            with get_connection() as conn:
                self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='rule_revisions'").fetchone())
                self.assertNotIn('lifecycle_managed',{r['name'] for r in conn.execute('PRAGMA table_info(detection_rules)')})
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0],3)
            initialize_database(); initialize_database()
            with get_connection() as conn:
                for old in before:
                    public=rules.public_record(conn,conn.execute('SELECT * FROM detection_rules WHERE id=?',(old['id'],)).fetchone())
                    self.assertEqual({k:public[k] for k in FIELDS},{k:old[k] for k in FIELDS})
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM rule_revisions').fetchone()[0],len(before))
                self.assertFalse(conn.execute('PRAGMA foreign_key_check').fetchall())

    def test_worker_crash_output_limit_and_blocked_stdin(self):
        original=validation.subprocess.Popen
        fixtures=[('import os; os._exit(7)','worker_crash'),
                  ('import sys; sys.stdin.buffer.read(); print("x"*40000)','output_limit'),
                  ('import time; time.sleep(20)','timeout')]
        for program,reason in fixtures:
            with self.subTest(reason=reason):
                def worker(command,**kwargs): return original([sys.executable,'-c',program],**kwargs)
                with patch.object(validation.subprocess,'Popen',side_effect=worker):
                    report=validation.run_validator({'rule_type':'YARA','code_content':'x'*204800})
                self.assertEqual(report['status'],'error'); self.assertEqual(report['reason'],reason)
                self.assertLess(report['duration_ms'],5000)

    def test_aggregate_quotas_rollback_and_export_survives_domain_event_limit(self):
        r=self.draft()
        with patch.dict(rules.LIMITS,snapshot_storage_bytes=0):
            self.request('POST','/api/rule-lifecycle/rules',{'title':'Over budget','code_content':SIGMA},expected=409)
        with patch.dict(rules.LIMITS,report_storage_bytes=0): self.action(r,'validate',expected=409)
        with get_connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM rule_validation_runs').fetchone()[0],0)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM rule_validation_claims').fetchone()[0],0)
        self.action(r,'validate'); r=self.action(r,'submit')
        with patch.dict(rules.LIMITS,review_storage_bytes=0):
            self.action(r,'review','reviewer',expected=409,decision='approved',reason='Over budget')
        with patch.dict(rules.LIMITS,event_storage_bytes=0): self.action(r,'withdraw',expected=409)
        self.assertEqual(rules.working(r['id'])['working']['state'],'in_review')
        with patch.dict(rules.LIMITS,events_per_rule=0):
            self.request('GET',f"/api/detection-rules/{r['id']}/revisions/export")
        self.assertTrue(verify_audit_log_integrity()['is_valid'])

    def test_managed_catalog_and_workbench_escape_untrusted_text(self):
        title='<script>alert("fixture")</script>'
        r=self.draft(title=title,rule_type='YARA',code_content=YARA)
        self.action(r,'validate'); r=self.action(r,'submit')
        r=self.action(r,'review','reviewer',decision='approved',reason='Escaping fixture')
        self.action(r,'publish','reviewer')
        page=self.client.get('/rules').text
        self.assertNotIn(title,page); self.assertIn('&lt;script&gt;',page)
        workbench=self.client.get(f"/rule-workbench/{r['id']}",headers=self.headers['owner']).text
        self.assertNotIn(title,workbench)

    def test_existing_over_quota_catalog_is_preserved_not_truncated(self):
        with get_connection() as conn:
            conn.executemany("INSERT INTO detection_rules(title,rule_type,code_content) VALUES (?,'YARA','rule Legacy { condition: true }')",
                             [(f'Existing legacy {number}',) for number in range(501)])
            manage_existing(conn)
        self.assertEqual(len(rules.public_rules()),502)
        self.assertEqual(rules.public_rules()[-1]['title'],'Existing legacy 500')
        self.request('POST','/api/rule-lifecycle/rules',{'title':'New over quota','code_content':SIGMA},expected=409)


if __name__=='__main__': unittest.main(verbosity=2)
