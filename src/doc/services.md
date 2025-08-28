# Service Installation

BreathGSLB ships sample service definitions under the
[`services/`](../services) directory for common init systems.

## Binding to privileged ports

BreathGSLB listens on port 53 by default. To permit a non-root binary to
bind to this port, grant it the `cap_net_bind_service` capability:

```bash
setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
```

If the daemon is started as root instead, it can bind to the port and then
optionally drop privileges after the sockets are open so it does not continue
running with full root access.

## systemd (Linux)

**Unit file:**
[`services/systemd/breathgslb.service`](../services/systemd/breathgslb.service)

Copy the unit file to `/etc/systemd/system/breathgslb.service` and optionally
set overrides in `/etc/breathgslb/env`.

```bash
groupadd --system breathgslb
useradd --system --no-create-home --gid breathgslb breathgslb
install -d /etc/breathgslb
cp /path/to/config.yaml /etc/breathgslb/config.yaml
systemctl daemon-reload
systemctl enable --now breathgslb.service
```

**Logs:** `journalctl -u breathgslb` (also
`/var/log/breathgslb/breathgslb.log` if file logging is enabled).

**Reload:** `systemctl reload breathgslb` (sends `SIGHUP`).

## OpenRC (Linux)

**Init script:** [`services/init.d/breathgslb`](../services/init.d/breathgslb)

Copy the script to `/etc/init.d/breathgslb`, edit the variables at the top,
and make it executable.

```bash
rc-update add breathgslb
rc-service breathgslb start
```

**Logs:** default `LOG_DIR` is `/var/log/breathgslb` with log file
`/var/log/breathgslb/breathgslb.log`.

**Reload:** `rc-service breathgslb reload` (sends `SIGHUP`).

## Windows Service

**Registry file:**
[`services/windows/breathgslb.reg`](../services/windows/breathgslb.reg)

Place `breathgslb.exe` and `config.yaml` in `C:\breathgslb` then run:

```cmd
reg import breathgslb.reg
net start BreathGSLB
```

**Logs:** `C:\breathgslb\breathgslb.log`.

**Reload:** not supported; restart with `net stop BreathGSLB` followed by
`net start BreathGSLB`.

## macOS (launchd)

**Property list:**
[`services/macos/breathgslb.plist`](../services/macos/breathgslb.plist)

Copy the plist to `/Library/LaunchDaemons/breathgslb.plist` and load it:

```bash
sudo launchctl load /Library/LaunchDaemons/breathgslb.plist
```

**Logs:** `/var/log/breathgslb.log`.

**Reload:** `sudo launchctl kill HUP net.breathgslb` (or unload/load the
plist).

## Packaging and Distribution

BreathGSLB can be packaged for multiple init systems.  The `install` targets
in the [`Makefile`](../Makefile) stage binaries, configuration trees, and
service files into a temporary root that packaging tools can consume.  For
example:

```bash
make DESTDIR=/tmp/pkgroot install-systemd   # or install-openrc
# then build your .deb, .rpm, .apk, etc. from /tmp/pkgroot
```

### Directory layout

Packages should create these directories with appropriate ownership:

- `/etc/breathgslb` for configuration
- `/var/log/breathgslb` for logs
- `/etc/breathgslb/keys`, `/etc/breathgslb/zones`, and
  `/etc/breathgslb/reverse` if those features are enabled

### systemd quirks

Install the unit file under the systemd directory used by the target
distribution (commonly `/lib/systemd/system`).  The unit expects an optional
environment file at `/etc/breathgslb/env` and logs to journald by default.  A
`tmpfiles.d` entry may be required to persist the log directory.

### OpenRC quirks

Place the init script at `/etc/init.d/breathgslb` and make it executable.
Post-install scripts usually run `rc-update add breathgslb default`.  Older
OpenRC releases run services as root when `command_user` is unset; verify the
script sets it and that the log directory is writable.

### Other targets

Windows packages typically copy the binary and configuration to
`C:\\breathgslb` and import `services/windows/breathgslb.reg` to create the
service.  macOS packages install the plist in `/Library/LaunchDaemons` and may
need to `chown` it to `root:wheel` so launchd will load it.

---

These service files are samples; adjust paths to match your environment.
