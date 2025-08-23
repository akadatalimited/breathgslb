# BreathGSLB Book

## Intro & Credits
BreathGSLB provides a lightweight authoritative DNS server with health‑checked global load balancing. This book collates the manual pages and extended guidance for deployment. Development was initiated by Akadata Limited and benefits from community contributions.

## Per-OS Service Setup
Service definitions for common init systems are under `services/`. Use the systemd unit on Linux distributions with systemd, the OpenRC script for Alpine and other OpenRC systems, and the Launchd plist for macOS. Each file is ready to install in `/etc` with the provided Makefile targets.

## Full Option Reference
Configuration keys allow fine‑grained control of behaviour including boolean toggles, interface lists, domain mappings, A/AAAA answers and zone types. The next appendix reproduces the full configuration manual derived from the `breathgslb.conf(5)` man page.

## DNS64 Explanation
When `dns64_prefix` is set, the server can synthesise AAAA records from A responses so IPv6‑only clients can reach IPv4 services. This follows RFC 6147 and applies only to zones where no AAAA records are defined.

## RFC1918 & ULA Addressing, Split-Horizon Design
Private IPv4 space (RFC1918) and IPv6 Unique Local Addresses allow internal deployments without leaking routes to the public Internet. Split‑horizon DNS can present different answers internally and externally by serving separate zones or views.

## API & TSIG Key Creation/Rotation
The optional HTTPS API exposes health and statistics endpoints. TSIG keys placed in the configured key directory enable signed zone transfers. Rotate keys by writing new key files and reloading the server; old keys can then be removed once slaves update.

## Deployment Scenarios
### Fast Primary
Run a fast primary in a region close to your users. Health checks ensure only healthy endpoints are served.

### Slow Backup
A secondary instance on slower infrastructure can act as backup. Configure higher probe intervals so it fails over when the primary is unreachable.

### Fallback Server
A low‑cost fallback can provide minimal answers if both primary and backup fail. Populate zones with limited records and longer TTLs.

## Command Reference
The following chapters were generated from the original man pages:

### breathgslb(8)

```markdown
{{breathgslb_manual}}
```

### breathgslb.conf(5)

```markdown
{{breathgslb_conf_manual}}
```
