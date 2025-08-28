# OpenRC init script for BreathGSLB

This directory contains an OpenRC init script for running the BreathGSLB
daemon.

## Installation

1. Copy `breathgslb` to `/etc/init.d/breathgslb`.
2. Review and adjust the variables at the top of the script to match your
   environment.
3. Create the `breathgslb` user and group (or ensure they already exist).
4. Make the script executable: `chmod +x /etc/init.d/breathgslb`.
5. Add the service to the desired runlevel: `rc-update add breathgslb`.
6. Start the service: `rc-service breathgslb start`.

## Customization

The script exposes variables for the log directory, log file, PID file, and
the user and group the daemon runs as. Additional command-line flags are
configurable through:

- `CONFIG_FILE` – path to the YAML configuration (default
  `/etc/breathgslb/config.yaml`).
- `LICENSE_PAYLOAD` – base64 license payload passed via `-license-payload` on
  startup so restarts do not require manual `-lp`.
- `EXTRA_ARGS` – any other flags to append to the command line.

Edit these variables to fit your installation before starting the service.

After the license is activated, the payload is written to
`/etc/breathgslb/license.payload` and loaded automatically, so no extra flags
are required in the init script and `LICENSE_PAYLOAD` can be left empty.

