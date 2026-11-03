#!/usr/bin/env python3
"""Retired unsafe administrator deletion helper. Never modifies a database."""


def reset_admin_setup():
    raise SystemExit('This destructive helper is retired; no accounts were deleted. '
        'Deleting administrators must not reopen public registration. Restore a verified '
        'backup or use an existing administrator to reset a password. See docs/storage-resilience.md.')


if __name__ == "__main__":
    reset_admin_setup()
