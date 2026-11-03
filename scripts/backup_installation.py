"""Private SQLite snapshot + installation config + optional managed signing key.

Use an operator timer, not the sleeping web process. No automatic retention/deletion.
Restore drills and an independent off-host copy are still required.
"""
import argparse
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from app.storage.local import (StorageError, atomic_private_write, check_location,
    data_directory, fsync_directory, load_manifest, private_read, require_tables, admin_required)
from scripts.backup_database import backup_database


def backup_installation(directory, output, include_managed_key=False, ephemeral=False):
    directory=Path(directory).absolute(); output=Path(output).absolute()
    check_location(output, ephemeral)
    profile=load_manifest(directory, required=True)
    if profile['state']!='ready': raise StorageError('initialization_incomplete')
    source=Path(profile['database_path'])
    check_location(source, profile['ephemeral'])
    if output==directory or directory in output.parents or source.parent==output:
        raise StorageError('independent_backup_directory_required')
    if include_managed_key and not profile['signing_key_file']:
        raise StorageError('signing_key_is_environment_managed')
    output.mkdir(parents=True,mode=0o700,exist_ok=True)
    if output.stat().st_uid!=os.getuid() or output.stat().st_mode & 0o077:
        raise StorageError('configuration_permissions')
    destination=output/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex)
    destination.mkdir(mode=0o700)
    # An incomplete directory is retained and clearly lacks backup.json; never
    # delete a prior good backup to disguise a failed operation.
    backup_database(source,destination/'dashboard.db')
    with sqlite3.connect((destination/'dashboard.db').as_uri()+'?mode=ro',uri=True) as conn:
        row=conn.execute('SELECT database_id FROM installation_metadata WHERE id=1').fetchone()
        if not row or row[0]!=profile['database_id']: raise StorageError('database_identity_mismatch')
        require_tables(conn,profile.get('required_tables',[]))
        admin_required(conn)
        head=conn.execute('SELECT id,integrity_hash FROM audit_logs ORDER BY id DESC LIMIT 1').fetchone()
    atomic_private_write(destination/'installation.json',json.dumps(profile,sort_keys=True,indent=2)+'\n')
    if include_managed_key:
        key_path=Path(profile['signing_key_file'])
        if key_path.parent!=directory or key_path.name!='signing.key':
            raise StorageError('signing_key_not_locally_managed')
        atomic_private_write(destination/'signing.key',private_read(key_path,maximum=4096,require_private=True))
    result={'format_version':1,'created_at':datetime.now(timezone.utc).isoformat(),
            'database_id':profile['database_id'],'sqlite_integrity':'ok',
            'audit_checkpoint':{'id':head[0],'integrity_hash':head[1]} if head else None,
            'managed_signing_key_included':include_managed_key,
            'notice':'Copy off-host and perform a restore drill. This is not proof of full audit-chain verification.'}
    atomic_private_write(destination/'backup.json',json.dumps(result,sort_keys=True,indent=2)+'\n')
    fsync_directory(destination); fsync_directory(output)
    return destination


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data-dir',default=str(data_directory()))
    p.add_argument('--output-dir',required=True)
    p.add_argument('--include-managed-key',action='store_true')
    p.add_argument('--allow-ephemeral-storage',action='store_true',help='Disposable backup tests only.')
    args=p.parse_args()
    try:
        destination=backup_installation(args.data_dir,args.output_dir,args.include_managed_key,args.allow_ephemeral_storage)
    except StorageError as exc:
        print(json.dumps({'status':'failed','code':exc.code})); return 1
    except Exception:
        print(json.dumps({'status':'failed','code':'backup_failed'})); return 1
    print(json.dumps({'status':'backup_verified','directory':str(destination)})); return 0


if __name__=='__main__': raise SystemExit(main())
