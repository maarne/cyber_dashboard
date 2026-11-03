"""Explicit SQLite provisioning/adoption. Never runs on ordinary web startup.

python -m scripts.configure_storage status --data-dir /var/lib/cyberdash
python -m scripts.configure_storage init --data-dir /var/lib/cyberdash --confirm-new
python -m scripts.configure_storage adopt --data-dir /var/lib/cyberdash --database /existing/app.db --confirm-adopt
"""
import argparse
import fcntl
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from app.storage.local import (StorageError, SETTINGS, check_location, data_directory,
    fsync_directory, installer_context, load_manifest, persistent_mount, private_read,
    save_manifest, require_tables, admin_required)


def inspect_database(path):
    """Read-only inventory; no app imports, seeding, journaling changes or secrets."""
    path = Path(path)
    if not path.is_file(): raise StorageError('database_missing')
    check_location(path, ephemeral=True)
    try:
        conn = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=5)
        try:
            if conn.execute('PRAGMA quick_check').fetchone()[0]!='ok': raise StorageError('database_integrity_failed')
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {'users','cves','detection_rules','audit_logs'}.issubset(tables):
                raise StorageError('unknown_database_schema')
            for table, required in {'users':{'id','username','password_hash','role'},
                    'cves':{'cve_id'},'detection_rules':{'id','title','code_content'},
                    'audit_logs':{'id','timestamp','username','action'}}.items():
                if not required.issubset({r[1] for r in conn.execute('PRAGMA table_info('+table+')')}):
                    raise StorageError('unknown_database_schema')
            versions = [r[0] for r in conn.execute('SELECT version FROM schema_migrations ORDER BY version')] if 'schema_migrations' in tables else []
            if any(v not in (1,2,3,4) for v in versions): raise StorageError('unsupported_database_schema')
            if versions and versions!=list(range(1,max(versions)+1)): raise StorageError('unsupported_database_schema')
            identity = conn.execute('SELECT database_id FROM installation_metadata WHERE id=1').fetchone() if 'installation_metadata' in tables else None
            return {'database_id':identity[0] if identity else None, 'schema_versions':versions,
                    'counts':{t:conn.execute('SELECT COUNT(*) FROM '+t).fetchone()[0]
                              for t in ('users','cves','assets','cases','detection_rules','audit_logs') if t in tables}}
        finally: conn.close()
    except sqlite3.Error:
        raise StorageError('database_unavailable') from None


@contextmanager
def installation_lock(directory):
    directory = Path(directory)
    check_location(directory, ephemeral=True)
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.stat()
    if info.st_uid!=os.getuid() or info.st_mode & 0o077:
        raise StorageError('configuration_permissions')
    fd = os.open(directory/'.installation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise StorageError('installation_busy') from None
        yield
    finally: os.close(fd)


def signing_key(directory, adopt=False):
    value_present = 'JWT_SECRET_KEY' in os.environ
    file = os.environ.get('JWT_SECRET_KEY_FILE')
    if value_present and file is not None: raise StorageError('signing_key_configuration_conflict')
    if file is not None:
        file = Path(file).expanduser().absolute()
        value = private_read(file, maximum=4096).rstrip('\r\n')
    elif value_present:
        value = os.environ['JWT_SECRET_KEY']
    else:
        if adopt: raise StorageError('original_signing_key_required')
        file = directory/'signing.key'
        if file.exists() or file.is_symlink(): raise StorageError('signing_key_already_exists')
        value = secrets.token_hex(32)
        # O_EXCL makes a pre-existing key impossible to overwrite.
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(value+'\n'); stream.flush(); os.fsync(stream.fileno())
        fsync_directory(directory)
    if len(value.encode())<32 or value=='cyberdash-secret-key-change-in-production-2026':
        raise StorageError('signing_key_invalid')
    return str(file) if file is not None else None


def provision(args):
    from app.storage.local import require_sqlite_backend
    require_sqlite_backend()
    directory = Path(args.data_dir).expanduser().absolute()
    ephemeral = args.allow_ephemeral_storage
    check_location(directory, ephemeral)
    path = Path(args.database).expanduser().absolute() if args.database else directory/'cyber_dashboard.db'
    check_location(path, ephemeral)
    if Path('/.dockerenv').exists() and not ephemeral:
        if not persistent_mount(directory) or not persistent_mount(path):
            raise StorageError('persistent_volume_required')
    if not (args.confirm_new if args.command=='init' else args.confirm_adopt):
        raise StorageError('explicit_initialization_confirmation_required')
    with installation_lock(directory):
        if load_manifest(directory) is not None: raise StorageError('installation_already_configured')
        if args.command=='init':
            if path.exists() or path.is_symlink(): raise StorageError('database_already_exists')
            identity = str(uuid.uuid4())
        else:
            inventory = inspect_database(path)
            identity = inventory['database_id'] or str(uuid.uuid4())
        key_file = signing_key(directory, adopt=args.command=='adopt')
        if args.command=='adopt':
            from scripts.backup_database import backup_database
            backups = directory/'backups'
            backups.mkdir(mode=0o700, exist_ok=True)
            backup_database(path, backups/f'before-adoption-{uuid.uuid4().hex}.db')
        profile = {'format_version':1, 'backend':'sqlite', 'database_path':str(path),
            'operation':args.command,
            'database_id':identity, 'state':'initializing', 'signing_key_file':key_file,
            'ephemeral':ephemeral, 'created_at':datetime.now(timezone.utc).isoformat(),
            'settings':{k:os.environ[k] for k in SETTINGS if k in os.environ}}
        save_manifest(directory, profile)
        _initialize(directory, path)
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as conn:
            profile['required_tables']=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        profile['state']='ready'
        save_manifest(directory, profile)
        return {'status':'configured','backend':'sqlite','database_id':identity,
                'configuration_directory':str(directory),'disposable':ephemeral,
                'backup_created':args.command=='adopt'}


def _initialize(directory, path):
    # Import application settings only after durable configuration/key exists.
    os.environ['APP_DATA_DIR']=str(directory)
    os.environ['DATABASE_PATH']=str(path)
    from app.database import initialize_database
    from app.config import STORAGE_PROFILE
    with installer_context(): initialize_database(seed_defaults=STORAGE_PROFILE.get('operation')=='init')
    os.chmod(path, 0o600)
    fsync_directory(path.parent)


def resume(args):
    directory = Path(args.data_dir).expanduser().absolute()
    if not args.confirm_resume: raise StorageError('explicit_initialization_confirmation_required')
    with installation_lock(directory):
        profile = load_manifest(directory, required=True)
        if profile['state']!='initializing': raise StorageError('installation_not_incomplete')
        path = Path(profile['database_path'])
        # A removed file is recovery, not permission to make a second empty DB.
        if not path.is_file(): raise StorageError('database_missing')
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as conn:
            if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='installation_metadata'").fetchone():
                raise StorageError('database_identity_mismatch')
            row=conn.execute('SELECT database_id FROM installation_metadata WHERE id=1').fetchone()
            if not row or row[0]!=profile['database_id']: raise StorageError('database_identity_mismatch')
        _initialize(directory, path)
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as conn:
            profile['required_tables']=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        profile['state']='ready'; save_manifest(directory, profile)
        return {'status':'configured','database_id':profile['database_id']}


def status(args):
    profile = load_manifest(Path(args.data_dir).expanduser().absolute())
    if profile is None: return {'status':'storage_configuration_required'}
    inventory = inspect_database(Path(profile['database_path']))
    if inventory['database_id']!=profile['database_id']: raise StorageError('database_identity_mismatch')
    with sqlite3.connect(Path(profile['database_path']).as_uri()+'?mode=ro',uri=True) as conn:
        require_tables(conn,profile.get('required_tables',[]))
        admin_required(conn)
    return {'status':profile['state'],'backend':'sqlite','database_id':profile['database_id'],
            'disposable':profile['ephemeral'], **inventory}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    for command in ('init','adopt','resume','status','inspect'):
        p=sub.add_parser(command)
        p.add_argument('--data-dir',default=str(data_directory()))
        if command in ('init','adopt','inspect'): p.add_argument('--database',required=command in ('adopt','inspect'))
        if command in ('init','adopt'):
            p.add_argument('--allow-ephemeral-storage',action='store_true',help='Disposable/test storage only; permits temporary or unmounted paths.')
            p.add_argument('--confirm-'+('new' if command=='init' else 'adopt'),action='store_true')
        if command=='resume': p.add_argument('--confirm-resume',action='store_true')
    args=parser.parse_args()
    try:
        if args.command in ('init','adopt'): result=provision(args)
        elif args.command=='resume': result=resume(args)
        elif args.command=='inspect': result=inspect_database(Path(args.database).expanduser().absolute())
        else: result=status(args)
    except StorageError as exc:
        print(json.dumps({'status':'blocked','code':exc.code})); return 1
    except Exception:
        # Never echo a driver exception, settings value, credential or raw traceback.
        print(json.dumps({'status':'blocked','code':'storage_operation_failed'})); return 1
    print(json.dumps(result,sort_keys=True)); return 0


if __name__=='__main__': raise SystemExit(main())
