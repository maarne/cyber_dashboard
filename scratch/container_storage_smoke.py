"""Real two-worker restart/missing-file/restore drill; only uniquely named test volumes."""
import hashlib
import json
import secrets
import subprocess
import sys
import time
import uuid
import requests


def docker(*args): return subprocess.check_output(['docker',*args],text=True).strip()


def main(image):
    name='cyberdash-storage-smoke-'+uuid.uuid4().hex[:12]
    data=name+'-data'; backups=name+'-backups'; restored=name+'-restored'
    volumes=(data,backups,restored)
    for volume in volumes: docker('volume','create',volume)
    def run(volume,*command,backup=False):
        args=['run','--rm','--network','none','-v',volume+':/app/data']
        if backup: args+=['-v',backups+':/home/cyberdash/data']
        return docker(*args,'--entrypoint','python',image,'-B',*command)
    def start():
        docker('run','-d','--name',name,'-v',data+':/app/data','-p','127.0.0.1::8000',image)
        url='http://'+docker('port',name,'8000/tcp').splitlines()[0]
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            try:
                if requests.get(url+'/api/health',timeout=2).status_code==200: return url
            except requests.RequestException: pass
            time.sleep(.25)
        raise RuntimeError('Synthetic container did not become live.')
    def remove(): docker('rm','-f',name)
    try:
        refused=subprocess.run(['docker','run','--rm','--network','none','--entrypoint','python',image,
            '-B','-m','scripts.configure_storage','init','--data-dir','/app/data','--confirm-new'],capture_output=True,text=True)
        assert refused.returncode!=0 and 'persistent_volume_required' in refused.stdout
        run(data,'-m','scripts.configure_storage','init','--data-dir','/app/data','--confirm-new')
        url=start(); session=requests.Session(); password=secrets.token_urlsafe(24)+'Aa1!'
        assert session.post(url+'/api/setup',json={'username':'synthetic_owner','password':password},timeout=10).status_code==201
        response=session.post(url+'/api/detection-rules',json={'title':'Synthetic persistent rule','rule_type':'YARA','code_content':'rule DurableFixture { condition: true }'},timeout=10)
        assert response.status_code==201
        def fingerprint():
            return docker('exec',name,'python','-B','-c',"import hashlib; from pathlib import Path; print(hashlib.sha256(Path('/app/data/signing.key').read_bytes()).hexdigest())")
        original=fingerprint()
        run(data,'-m','scripts.backup_installation','--data-dir','/app/data','--output-dir','/home/cyberdash/data/backups','--include-managed-key',backup=True)
        remove(); url=start()
        assert fingerprint()==original
        assert session.get(url+'/api/auth/me',timeout=10).status_code==200  # Old cookie remains valid, no key replacement.
        assert any(r['title']=='Synthetic persistent rule' for r in session.get(url+'/api/detection-rules',timeout=10).json())
        docker('exec',name,'python','-B','-c',"from pathlib import Path; Path('/app/data/cyber_dashboard.db').rename('/app/data/held.db')")
        assert requests.get(url+'/api/ready',timeout=10).status_code==503
        assert requests.post(url+'/api/setup',json={'username':'no_reset','password':password},timeout=10).status_code==503
        remove(); url=start()
        assert requests.get(url+'/api/health',timeout=10).status_code==200
        assert requests.get(url+'/api/ready',timeout=10).json()['code']=='database_missing'
        assert docker('exec',name,'python','-B','-c',"from pathlib import Path; print(Path('/app/data/cyber_dashboard.db').exists())")=='False'
        remove()
        run(data,'-c',"from pathlib import Path; Path('/app/data/held.db').rename('/app/data/cyber_dashboard.db')")
        url=start(); assert session.get(url+'/api/auth/me',timeout=10).status_code==200
        remove()
        run(restored,'-c',"""from pathlib import Path
import shutil
root=next(Path('/home/cyberdash/data/backups').iterdir())
for before,after in [('dashboard.db','cyber_dashboard.db'),('installation.json','installation.json'),('signing.key','signing.key')]:
    shutil.copy2(root/before,Path('/app/data')/after)
from app.database import get_connection
from app.services.audit_service import verify_audit_log_integrity
with get_connection() as c:
    assert c.execute("SELECT COUNT(*) FROM users WHERE username='synthetic_owner'").fetchone()[0]==1
    assert c.execute("SELECT COUNT(*) FROM detection_rules WHERE title='Synthetic persistent rule'").fetchone()[0]==1
assert verify_audit_log_integrity()['is_valid']
print('isolated_restore_verified')
""",backup=True)
        print('Storage smoke passed: unmounted storage refused; generated key/account/rule/session survived two-worker replacement; missing DB stayed missing and registration closed; independent-volume restore verified.')
    finally:
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for volume in volumes:
            subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)


if __name__=='__main__': main(sys.argv[1] if len(sys.argv)>1 else 'cyberdash:storage-resilience')
