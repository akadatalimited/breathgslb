# BreathGSLB Book

## Intro & Credits
BreathGSLB provides a lightweight authoritative DNS server with
health‑checked global load balancing. This book collates the manual pages and
extended guidance for deployment. Development was initiated by Akadata
Limited and benefits from community contributions.

## Per-OS Service Setup
Service definitions for common init systems are under `services/`. Use the
systemd unit on Linux distributions with systemd, the OpenRC script for
Alpine and other OpenRC systems, and the Launchd plist for macOS. Each file
is ready to install in `/etc` with the provided Makefile targets.

## Full Option Reference
Configuration keys allow fine‑grained control of behaviour including boolean
toggles, interface lists, domain mappings, A/AAAA answers and zone types. The
next appendix reproduces the full configuration manual derived from the
`breathgslb.conf(5)` man page.

## DNS64 and NAT64
Setting `dns64_prefix` enables DNS64 as defined in RFC 6147. When an IPv6‑only
client asks for a AAAA record and none exist, BreathGSLB embeds the IPv4 A
answer into the prefix and returns a synthetic AAAA. The client then connects
through a NAT64 gateway to reach the legacy service.

```
[IPv6 client] --AAAA?--> [BreathGSLB DNS64] --A?--> [IPv4 server]
                 <--AAAA--                  <--A--
```

This allows modern IPv6 networks to continue using IPv4‑only applications
without assigning new public addresses.

## RFC1918 & ULA Addressing, Split-Horizon Design

### Local vs. Global Routing
RFC1918 defines private IPv4 ranges (10/8, 172.16/12, 192.168/16) that must
never appear on the public Internet. IPv6 offers Unique Local Addresses (ULAs)
under `fc00::/7` (commonly `fd00::/8`) which are likewise kept local but can be
generated with globally unique prefixes. Publicly routable services should use
global IPv6 and non‑RFC1918 IPv4 addresses; internal‑only hosts
should reside in RFC1918 or ULA space.

### Prioritising Internal Addresses
Split‑horizon deployments run separate internal and external views. In the
internal view, place private or ULA addresses before public ones so clients stay
on local networks whenever possible:

```
a_master_private:
  - 10.0.0.10
  - 10.0.0.11
a_master:
  - 203.0.113.10

ula_master:
  - fd00:1::10
aaaa_master:
  - 2001:db8::10
```

```
internal client -> resolver -> 10.0.0.10, 203.0.113.10
                 (prefers first, remains on LAN)
```

External views omit the private records, ensuring global users only see
publicly routable addresses.

## API & TSIG Key Creation/Rotation
The optional HTTPS API exposes health and statistics endpoints. TSIG keys
placed in the configured key directory enable signed zone transfers. Rotate
keys by writing new key files and reloading the server; old keys can then be
removed once slaves update.

## Deployment Scenarios
### Fast Primary
Run a fast primary in a region close to your users. Health checks ensure only
healthy endpoints are served.

### Slow Backup
A secondary instance on slower infrastructure can act as backup. Configure
higher probe intervals so it fails over when the primary is unreachable.

### Fallback Server
A low‑cost fallback can provide minimal answers if both primary and backup
fail. Populate zones with limited records and longer TTLs.

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
