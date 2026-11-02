"""Operator-only pause after restore. Uses configured DB; sends no network traffic."""
import argparse
import json
import time


def pause():
    from app.config import DATABASE_PATH
    from app.database import get_connection
    from app.services.audit_service import log_audit_event
    if not DATABASE_PATH.is_file():
        raise RuntimeError('Configured database does not exist; no file created.')
    with get_connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        if not conn.execute('SELECT 1 FROM schema_migrations WHERE version=2').fetchone():
            raise RuntimeError('Upgrade the restored database before pausing network features.')
        for table in ('asset_monitor_configs', 'asset_discovery_profiles'):
            rows = conn.execute(f'SELECT rowid AS config_row_id,settings_json FROM {table}').fetchall()
            for row in rows:
                settings = json.loads(row['settings_json']); settings['enabled'] = False
                conn.execute(f'UPDATE {table} SET enabled=0,next_due=NULL,generation=generation+1,row_version=row_version+1,settings_json=? WHERE rowid=?',
                             (json.dumps(settings), row['config_row_id']))
        conn.execute("UPDATE asset_network_jobs SET status='cancelled',completed_at=?,result_json=? WHERE status IN ('queued','running')",
                     (time.time(), json.dumps({'reason': 'operator_pause_after_restore'})))
        conn.execute('DELETE FROM asset_discovery_import_previews')
        log_audit_event('host-operator', 'system', 'ASSET_NETWORK_PAUSED_AFTER_RESTORE', resource_type='ASSET',
                        details='Disabled monitor/discovery configurations, cancelled outstanding jobs and invalidated discovery import tokens.', connection=conn)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pause all asset network activity in the configured DB. Stop the app before a restore.')
    parser.add_argument('--confirm', action='store_true', help='Confirm this write to DATABASE_PATH')
    args = parser.parse_args()
    if not args.confirm:
        parser.error('--confirm is required; no changes made')
    pause()
    print('Asset monitoring/discovery paused. Explicit review/re-enablement required; data retained.')
