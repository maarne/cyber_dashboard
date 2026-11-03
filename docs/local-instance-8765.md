# Persistent local instance on port 8765

Fresh installation activated on 2026-11-02 at the user's request. This replaces
the unavailable temporary runtime with a **new** dataset, not a recovery of its
lost records. The older workspace-root database was left unchanged.

## Installed configuration

- LAN URL: `http://192.168.0.158:8765` (current server LAN address).
- Listener: `0.0.0.0:8765` on all IPv4 interfaces, enabled at the user's request on
  2026-11-03. Local access at `http://127.0.0.1:8765` remains available.
- Service owner: `maarne`; two Gunicorn/Uvicorn workers.
- Code: `/home/maarne/apps/antigravity/cyber_dashboard`.
- Persistent installation: `/home/maarne/.local/share/cyberdash`.
- Database: `cyber_dashboard.db` inside that installation directory.
- Private settings/key: `installation.json` and `signing.key` in that same directory.
- Local backup bundles: `/home/maarne/.local/share/cyberdash-backups`.
- User units installed in `/home/maarne/.config/systemd/user/`:
  `cyberdash.service`, `cyberdash-backup.service`, `cyberdash-backup.timer`.

Installation/backup directories are 0700; DB/config/key files are 0600. No signing
key was printed or placed in a unit file. The app service uses the persisted
profile/key and excludes conflicting ambient database/signing-key variables.
Implemented asset, case and rule-lifecycle features are enabled in the profile;
no assets, scan targets, monitor jobs, automatic feed schedule or live test rules
were created. RFC1918 remains the default permitted asset scope.

The first administrator is created by the user at `/setup`; no password or test
account was provisioned by the assistant. The initial backup predates that account;
run another backup after setup if an immediate account backup is desired.

## Startup and backups

The user service and timer are enabled. `loginctl show-user maarne -p Linger`
reported `Linger=yes`, so this user's service manager starts at boot without
requiring an interactive login. The app restarts on failure and is independent
of the OpenCode session/its background launchers.

The timer runs daily with up to 15 minutes of randomized delay, and schedules a
post-boot backup. `Persistent=true` catches missed calendar runs after downtime.
Each bundle includes a consistent DB snapshot, private installation configuration,
the generated signing key, integrity/identity checks and a completion record.
Previous backups are not automatically deleted; monitor space and choose retention.

Manage as `maarne`:

```bash
systemctl --user status cyberdash.service
systemctl --user restart cyberdash.service
systemctl --user list-timers cyberdash-backup.timer
systemctl --user start cyberdash-backup.service
journalctl --user -u cyberdash.service -n 50 --no-pager
journalctl --user -u cyberdash-backup.service -n 30 --no-pager
```

Do **not** run `configure_storage init` again after reboot. Never delete the
installation manifest/key to bypass a recovery warning. If the checkout moves,
update both units' code/virtualenv paths, reload the user manager and verify service
startup before removing the old checkout.

## Verified after installation

- HTTP health/readiness and the administrator setup page return 200.
- Controlled service restart preserved the same DB UUID, contents and signing key.
- Service/timer enabled; user-manager boot persistence confirmed.
- Backup service succeeded. Backup DB integrity and matching saved key verified.
- A backup was copied into a separate private disposable directory, reopened with
  the copied configuration/key, and checked for schema/identity, expected fresh
  contents and audit integrity. Live data and the original backup were not changed.
- The older workspace database remained unchanged. No host reboot was performed.

## Network access

The installed user service binds port 8765 on all IPv4 interfaces, including LAN
and Tailscale. The bind setting persists across service/host restarts. The local
readiness check confirmed administrator setup was complete before enabling network
access. No router forwarding, public tunnel or firewall policy was added. HTTP is
appropriate only on a trusted network; use HTTPS before public/untrusted exposure.
Firewall/router policies and remote-client reachability are separate from the app
listener and must allow the intended clients.

**These backups are local on the same server.** They protect against the previous
temporary-directory/reboot failure and help with accidental application changes,
but not host/disk loss. An encrypted off-server copy still needs an approved
destination; none was invented or configured. See [storage recovery](storage-resilience.md).
