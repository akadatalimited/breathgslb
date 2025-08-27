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
the user and group the daemon runs as. Edit these variables to fit your
installation before starting the service.

After the license is activated, the payload is written to
`/etc/breathgslb/license.payload` and loaded automatically, so no extra flags
are required in the init script.

