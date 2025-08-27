# macOS service files for BreathGSLB

This directory provides launchd and legacy StartupItem configurations for
running the BreathGSLB daemon on macOS.

## Installation (launchd)

1. Copy `breathgslb.plist` to `/Library/LaunchDaemons/breathgslb.plist`.
2. Review and adjust the paths in the plist to match your environment.
3. Load and start the service:

   ```bash
   sudo launchctl load /Library/LaunchDaemons/breathgslb.plist
   ```

   After activation, the license payload is stored at
   `/etc/breathgslb/license.payload`, so the service can start without specifying
   `-license-payload`.

## Uninstallation (launchd)

```bash
sudo launchctl unload /Library/LaunchDaemons/breathgslb.plist
sudo rm /Library/LaunchDaemons/breathgslb.plist
```

## Installation (StartupItem legacy)

1. Create the directory `/Library/StartupItems/BreathGSLB`.
2. Copy the `breathgslb` script to `/Library/StartupItems/BreathGSLB/BreathGSLB`
   and make it executable:

   ```bash
   sudo cp breathgslb /Library/StartupItems/BreathGSLB/BreathGSLB
   sudo chmod +x /Library/StartupItems/BreathGSLB/BreathGSLB
   ```

3. (Optional) Add a `StartupParameters.plist` if your platform requires
   dependency information.

The daemon will then start at boot via the legacy rc mechanism.

## Uninstallation (StartupItem)

```bash
sudo rm -r /Library/StartupItems/BreathGSLB
```

## launchd vs. StartupItem

* **launchd** is the modern service manager on macOS (10.4+). It supervises the
  daemon, restarts it if it exits unexpectedly, and is managed with `launchctl`.
* **StartupItem** is a deprecated mechanism for pre-launchd systems. It merely
  runs the script at boot and offers no supervision or restart capability.
* On current macOS releases, launchd is preferred and StartupItems may be
  ignored entirely.
