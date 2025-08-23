# Service Installation

BreathGSLB ships sample service definitions under the [`services/`](../services) directory for common init systems.

## systemd (Linux)

**Unit file:** [`services/systemd/breathgslb.service`](../services/systemd/breathgslb.service)

Copy the unit file to `/etc/systemd/system/breathgslb.service` and optionally set overrides in `/etc/breathgslb/env`.

```bash
groupadd --system breathgslb
useradd --system --no-create-home --gid breathgslb breathgslb
install -d /etc/breathgslb
cp /path/to/config.yaml /etc/breathgslb/config.yaml
systemctl daemon-reload
systemctl enable --now breathgslb.service
```

**Logs:** `journalctl -u breathgslb` (also `/var/log/breathgslb/breathgslb.log` if file logging is enabled).

**Reload:** `systemctl reload breathgslb` (sends `SIGHUP`).

## OpenRC (Linux)

**Init script:** [`services/init.d/breathgslb`](../services/init.d/breathgslb)

Copy the script to `/etc/init.d/breathgslb`, edit the variables at the top, and make it executable.

```bash
rc-update add breathgslb
rc-service breathgslb start
```

**Logs:** default `LOG_DIR` is `/var/log/breathgslb` with log file `/var/log/breathgslb/breathgslb.log`.

**Reload:** `rc-service breathgslb reload` (sends `SIGHUP`).

## Windows Service

**Registry file:** [`services/windows/breathgslb.reg`](../services/windows/breathgslb.reg)

Place `breathgslb.exe` and `config.yaml` in `C:\breathgslb` then run:

```cmd
reg import breathgslb.reg
net start BreathGSLB
```

**Logs:** `C:\breathgslb\breathgslb.log`.

**Reload:** not supported; restart with `net stop BreathGSLB` followed by `net start BreathGSLB`.

## macOS (launchd)

**Property list:** [`services/macos/breathgslb.plist`](../services/macos/breathgslb.plist)

Copy the plist to `/Library/LaunchDaemons/breathgslb.plist` and load it:

```bash
sudo launchctl load /Library/LaunchDaemons/breathgslb.plist
```

**Logs:** `/var/log/breathgslb.log`.

**Reload:** `sudo launchctl kill HUP net.breathgslb` (or unload/load the plist).

---

These service files are samples; adjust paths to match your environment.
