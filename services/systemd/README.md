# Systemd service for BreathGSLB

This directory provides a systemd unit file for running the BreathGSLB daemon.

## Installation

1. Copy `breathgslb.service` to `/etc/systemd/system/breathgslb.service`.
2. Create a dedicated `breathgslb` user and group for the service:
   ```bash
   groupadd --system breathgslb
   useradd --system --no-create-home --gid breathgslb breathgslb
   ```
3. Create configuration and environment directories:
   ```bash
   install -d /etc/breathgslb
   cp /path/to/config.yaml /etc/breathgslb/config.yaml
   touch /etc/breathgslb/env
   ```
   The license payload is saved to `/etc/breathgslb/license.payload` after
   activation, so subsequent starts do not require `-license-payload`.
4. Enable and start the service:
   ```bash
   systemctl daemon-reload
   systemctl enable --now breathgslb.service
   ```

## Customization

Settings in `/etc/breathgslb/env` override defaults:

- `BREATHGSLB_CONFIG` – path to the configuration file (default
  `/etc/breathgslb/config.yaml`).

After activation, the daemon reads `/etc/breathgslb/license.payload`
automatically, so extra flags are unnecessary.

After editing the environment file or configuration, reload the service without
full restart:

```bash
systemctl reload breathgslb
```

This sends `SIGHUP` via `ExecReload=/bin/kill -HUP $MAINPID` so the daemon
re-reads its configuration.
