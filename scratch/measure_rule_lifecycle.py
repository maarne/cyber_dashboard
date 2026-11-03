"""Synthetic-only bounded dataset/validator measurements; never opens the runtime DB."""
from scratch import test_support
import json
import os
import resource
import statistics
import time
os.environ['FEATURE_RULE_LIFECYCLE']='true'
from app.database import initialize_database,get_connection
from app.models.rule_schemas import RuleSnapshot,RevisionRequest
from app.services import auth_service as auth,rule_lifecycle_service as rules,rule_validation_service as validation


def main():
    test_support.assert_test_database(); initialize_database()
    auth.complete_initial_setup('measurement',auth.generate_secure_random_password(20))
    user=auth.get_user_by_username('measurement')
    actor={'username':user['username'],'role':user['role'],'user_id':user['id']}
    source='/*'+'x'*50000+'*/\nrule Measurement { condition: true }'
    start=time.monotonic()
    for number in range(485):
        snapshot=RuleSnapshot(title=f'Synthetic measurement {number}',rule_type='YARA',code_content=source)
        rule=rules.create(snapshot.model_dump(),actor)
        rules.new_revision(rule['id'],RevisionRequest(**snapshot.model_dump(),expected_version=rule['row_version'],
            expected_parent_revision_id=rule['working']['id']),actor)
    def measured(fn):
        times=[]
        for _ in range(5):
            began=time.monotonic(); fn(); times.append((time.monotonic()-began)*1000)
        return round(statistics.median(times),2)
    results={'fixture_build_seconds':round(time.monotonic()-start,2),
             'working_page_20_median_ms':measured(lambda:rules.list_working(limit=20)),
             'public_catalog_median_ms':measured(rules.public_rules)}
    with get_connection() as conn:
        results.update(identities=conn.execute('SELECT COUNT(*) FROM detection_rules').fetchone()[0],
            revisions=conn.execute('SELECT COUNT(*) FROM rule_revisions').fetchone()[0],
            snapshot_bytes=conn.execute('SELECT SUM(payload_bytes) FROM rule_revisions').fetchone()[0],
            history_plan=[r['detail'] for r in conn.execute('EXPLAIN QUERY PLAN SELECT * FROM rule_revisions WHERE rule_id=? AND id<? ORDER BY id DESC LIMIT 21',(rule['id'],2**62))])
    from scratch.test_rule_lifecycle import SIGMA,YARA
    for kind,source in (('Sigma',SIGMA),('YARA',YARA)):
        reports=[validation.run_validator({'rule_type':kind,'code_content':source}) for _ in range(3)]
        assert all(r['status']=='valid' for r in reports),reports
        results[kind.lower()+'_median_ms']=round(statistics.median(r['duration_ms'] for r in reports),2)
    results['validator_children_peak_rss_kib']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    print(json.dumps(results,indent=2))


if __name__=='__main__': main()
