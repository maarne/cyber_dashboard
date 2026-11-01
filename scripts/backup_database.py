"""Consistent SQLite backups, including committed WAL content when present.

Usage: python -m scripts.backup_database --database /path/app.db --output /backup/new.db
This utility does not import/start the application and never overwrites files.
"""

import argparse
import os
import sqlite3
from contextlib import closing
from pathlib import Path


def backup_database(database: Path, output: Path):
    source = database.resolve(strict=True)
    destination = output.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src, closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup integrity check failed.")
    except Exception:
        # Only remove the destination file this call created, never the source.
        destination.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    backup_database(args.database, args.output)
