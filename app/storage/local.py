"""Durable SQLite installation metadata; independent of application config/auth."""
import json
import os
import re
import stat
import tempfile
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

MANIFEST = 'installation.json'
SETTINGS = frozenset(('ENV', 'PUBLIC_BASE_URL', 'FEATURE_ASSET_PRIORITIZATION',
    'FEATURE_ASSET_MONITORING', 'FEATURE_ASSET_DISCOVERY', 'FEATURE_CASE_MANAGEMENT',
    'FEATURE_RULE_LIFECYCLE', 'ASSET_PROBE_ALLOWED_CIDRS', 'ASSET_PROBE_SCOPE_LABEL',
    'ASSET_PROBE_RATE_PER_MINUTE', 'ASSET_DISCOVERY_RATE_PER_MINUTE',
    'ASSET_PROBE_DNS_RATE_PER_MINUTE', 'ASSET_INTEL_STALE_HOURS'))
_installer = ContextVar('storage_installer', default=False)


class StorageError(RuntimeError):
    """Only fixed, nonsecret error codes may be returned publicly."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def enabled(value):
    return str(value).lower() in ('1', 'true', 'yes')


def require_sqlite_backend():
    if os.getenv('DB_TYPE', 'sqlite') != 'sqlite' or any(k in os.environ for k in
            ('DATABASE_URL','DATABASE_URL_FILE','DB_HOST','DB_PORT','DB_NAME','DB_USER','DB_PASSWORD','DB_PASSWORD_FILE')):
        raise StorageError('external_database_not_supported_yet')


def data_directory():
    value = os.environ.get('APP_DATA_DIR')
    if value is not None:
        if not value.strip(): raise StorageError('configuration_invalid')
        path = Path(value).expanduser()
    else:
        path = Path(os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local/share')))/'cyberdash'
    if not path.is_absolute(): raise StorageError('configuration_invalid')
    return path


def private_read(path, maximum=65536, require_private=False):
    """Do not follow a swapped symlink or read an unbounded secret/config file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise StorageError('configuration_invalid')
            if require_private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
                raise StorageError('configuration_permissions')
            value = stream.read(maximum+1)
        if len(value) > maximum: raise StorageError('configuration_invalid')
        return value.decode('utf-8')
    except StorageError:
        raise
    except (OSError, UnicodeError):
        raise StorageError('configuration_unreadable') from None


def load_manifest(directory, required=False):
    path = Path(directory)/MANIFEST
    if not path.exists() and not path.is_symlink():
        if required: raise StorageError('storage_configuration_required')
        return None
    try:
        check_location(Path(directory), ephemeral=True)
        parent = Path(directory).stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise StorageError('configuration_permissions')
        value = json.loads(private_read(path, require_private=True))
        if (not isinstance(value, dict) or value.get('format_version') != 1
                or value.get('backend') != 'sqlite' or value.get('state') not in ('initializing', 'ready')
                or not isinstance(value.get('database_path'), str)
                or not Path(value['database_path']).is_absolute()
                or str(uuid.UUID(value['database_id'])) != value['database_id']
                or not isinstance(value.get('settings'), dict)
                or any(k not in SETTINGS or not isinstance(v, str) or len(v)>4096 for k,v in value['settings'].items())
                or not isinstance(value.get('ephemeral'), bool)
                or not isinstance(value.get('required_tables', []), list)
                or len(value.get('required_tables', []))>128
                or any(not isinstance(t,str) or not re.fullmatch(r'[A-Za-z][A-Za-z_0-9]{0,62}',t)
                       for t in value.get('required_tables', []))
                or (value.get('signing_key_file') is not None and
                    (not isinstance(value['signing_key_file'],str) or not Path(value['signing_key_file']).is_absolute()))):
            raise ValueError()
        return value
    except StorageError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        raise StorageError('configuration_invalid') from None


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def atomic_private_write(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        if path.is_symlink(): raise StorageError('configuration_invalid')
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def save_manifest(directory, value):
    atomic_private_write(Path(directory)/MANIFEST, json.dumps(value, sort_keys=True, indent=2)+'\n')


def check_location(path, ephemeral=False):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or path.resolve()!=path:
        raise StorageError('unsafe_storage_path')
    if not ephemeral and any(path == root or root in path.parents for root in (Path('/tmp'), Path('/var/tmp'), Path('/run'), Path('/dev/shm'))):
        raise StorageError('ephemeral_storage_refused')


def persistent_mount(path):
    """Best-effort Linux container mount check, not a durability guarantee."""
    path = Path(path)
    try:
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            target = Path(line.split()[4].replace('\\040', ' '))
            if target != Path('/') and (target == path or target in path.parents): return True
    except (OSError, IndexError):
        pass
    return False


@contextmanager
def installer_context():
    token = _installer.set(True)
    try: yield
    finally: _installer.reset(token)


def installing():
    return _installer.get()


def validate_connection(conn, database_path):
    """No implicit adoption, creation or mutation on ordinary connections."""
    if installing(): return
    from app import config
    required_tables = []
    if config.ALLOW_EPHEMERAL_STORAGE:
        expected = config.EXPECTED_DATABASE_ID
    else:
        manifest = load_manifest(config.APP_DATA_DIR, required=True)
        if manifest['state'] != 'ready': raise StorageError('initialization_incomplete')
        if Path(manifest['database_path']) != Path(database_path):
            raise StorageError('database_identity_mismatch')
        expected = config.EXPECTED_DATABASE_ID or manifest['database_id']
        if expected != manifest['database_id']: raise StorageError('database_identity_mismatch')
        required_tables = manifest.get('required_tables', [])
    if expected:
        try:
            row = conn.execute('SELECT database_id FROM installation_metadata WHERE id=1').fetchone()
        except Exception:
            raise StorageError('database_identity_mismatch') from None
        if not row or row[0] != expected: raise StorageError('database_identity_mismatch')
    require_tables(conn, required_tables)


def require_tables(conn, required_tables):
    if required_tables:
        actual = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not set(required_tables).issubset(actual): raise StorageError('schema_incomplete')


def add_identity(conn):
    from app import config
    conn.execute('''CREATE TABLE IF NOT EXISTS installation_metadata (
        id INTEGER PRIMARY KEY CHECK(id=1), database_id TEXT NOT NULL UNIQUE,
        admin_setup_completed INTEGER NOT NULL DEFAULT 0 CHECK(admin_setup_completed IN (0,1)))''')
    row = conn.execute('SELECT database_id FROM installation_metadata WHERE id=1').fetchone()
    expected = (config.STORAGE_PROFILE or {}).get('database_id') or config.EXPECTED_DATABASE_ID
    if row and expected and row[0]!=expected: raise StorageError('database_identity_mismatch')
    if not row:
        conn.execute('INSERT INTO installation_metadata VALUES (1,?,?)',
                     (expected or str(uuid.uuid4()), int(bool(conn.execute('SELECT 1 FROM users LIMIT 1').fetchone()))))


def admin_required(conn):
    has_admin = bool(conn.execute("SELECT 1 FROM users WHERE role='admin'").fetchone())
    marker = conn.execute('SELECT admin_setup_completed FROM installation_metadata WHERE id=1').fetchone()
    if not has_admin and marker and marker[0]: raise StorageError('administrator_recovery_required')
    return not has_admin
