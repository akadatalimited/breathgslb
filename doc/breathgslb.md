# BreathGSLB Book

## Intro & Credits
BreathGSLB provides a lightweight authoritative DNS server with health‑checked
global load balancing. This book collates the manual pages and extended guidance
for deployment. Development was initiated by Akadata Limited and benefits from
community contributions.

## Per-OS Service Setup
Service definitions for common init systems are under `services/`. Use the
systemd unit on Linux distributions with systemd, the OpenRC script for Alpine
and other OpenRC systems, and the Launchd plist for macOS. Each file is ready to
install in `/etc` with the provided Makefile targets.

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
global IPv6 and non‑RFC1918 IPv4 addresses; internal‑only hosts should reside in
RFC1918 or ULA space.

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
The optional HTTPS API exposes health and statistics endpoints. TSIG keys placed
in the configured key directory enable signed zone transfers. Rotate keys by
writing new key files and reloading the server; old keys can then be removed
once slaves update.

## Deployment Scenarios
### Fast Primary
Run a fast primary in a region close to your users. Health checks ensure only
healthy endpoints are served.

### Slow Backup
A secondary instance on slower infrastructure can act as backup. Configure
higher probe intervals so it fails over when the primary is unreachable.

### Fallback Server
A low‑cost fallback can provide minimal answers if both primary and backup fail.
Populate zones with limited records and longer TTLs.

## Command Reference
The following chapters were generated from the original man pages:

### breathgslb(8)

```markdown
# NAME
breathgslb - health‑checked authoritative DNS with global load balancing
# SYNOPSIS
**breathgslb**
[ -config file ]
[ -api-listen addr ]
[ -api-token token ]
[ -api-cert file ]
[ -api-key file ]
[ -supervisor path ]
[ -debug-pprof ]
# DESCRIPTION
**BreathGSLB**
is a compact authoritative server that selects A and AAAA answers based on
live health checks.  It serves normal DNS records while optionally
synthesising AAAA from A via DNS64.  The daemon listens on UDP and TCP for
both IPv4 and IPv6 and can expose an HTTPS admin API for health and
statistics.
# DNS64
When no AAAA record exists for a name,
**breathgslb**
can synthesise one from an A record using the configured
**dns64_prefix .**
The IPv4 address is embedded into the prefix and returned to the
client, allowing an IPv6‑only host to reach a legacy IPv4 service via
an external NAT64 gateway.

Client AAAA?  -> BreathGSLB ->  A?   -> IPv4 server
       <- AAAA   DNS64      <-  A   <-
This bridges IPv6‑only networks to IPv4 infrastructure without exposing
new public addresses.
# OPTIONS
## -config " " file
Path to the YAML configuration file.  Defaults to
## -api-listen " " addr
Bind address for the optional HTTPS admin API, e.g.
**:9443**
or
127.0.0.1:9443 .
## -api-token " " token
Bearer token for API requests.  May be a literal string or
path to a file whose contents are used.
## -api-cert " " file
TLS certificate file for the admin API.
## -api-key " " file
TLS private key for the admin API.
## -supervisor " " path
Send service state change notifications to the given supervisor socket
or FIFO.  The format of the messages is supervisor specific.
## -debug-pprof
Enable Go's pprof debug server on
localhost:6060 .
# USAGE
Start the daemon with a configuration file:

breathgslb -config /etc/breathgslb/config.yaml

For split‑horizon deployments run separate instances with differing
configuration files and distinct listeners.  Share TSIG keys between
instances when signed zone transfers are required.

TLS certificates and API tokens are read from the paths supplied on the
command line or in the configuration file.  To rotate them atomically,
write the new material to a separate file, update a symlink, and reload
**breathgslb**
with
**SIGHUP**
or a restart.
# SEE ALSO
breathgslb.conf (5)```

### breathgslb.conf(5)

```markdown
# NAME
breathgslb.conf - configuration file for breathgslb
# DESCRIPTION
The configuration file is written in YAML and controls listener
addresses, health checking, and record synthesis.  A minimal file
contains global settings followed by one or more zone blocks.
# GLOBAL KEYS
## listen
Address or
:port
on which to bind.  The daemon listens on UDP and TCP for both
IPv4 and IPv6.
## listen_addrs
List of explicit
**host:port**
bindings.  Overrides
interfaces .
## interfaces
List of network interface names whose addresses are used for
binding.
## reverse_dir
Directory where automatically generated reverse zones are written.
## zones_dir
Directory containing forward zone files.  Each file named `<zone>.fwd.yaml`
is parsed and appended to the `zones` list.
## timeout_sec
Per‑probe timeout in seconds.
## interval_sec
Base interval between probe rounds in seconds.
## rise
Consecutive successes required to mark an endpoint up.
## fall
Consecutive failures required to mark an endpoint down.
## jitter_ms
Random jitter added to each interval.
## cooldown_sec
Minimum seconds between state flips for an address family.
## dns64_prefix
IPv6 prefix used when synthesizing AAAA from A records.
## edns_buf
Advertised EDNS0 UDP payload size.
## max_records
Hard limit on A/AAAA records per response.
## log_queries
Log DNS queries and health transitions.
## max_workers
Number of UDP worker goroutines.
## log_syslog
Send logs to syslog instead of stderr.
## tsig.path
Directory containing emitted TSIG key files.
## geoip.enabled
Enable GeoIP lookups for location based routing.
## api
Enable the HTTPS admin API.
## api-listen
Port for the admin API; default 9443.
## api-interface
Interface name or list of interfaces to bind the API.
## api-token
Path to a file containing the bearer token or the literal token
string.
## api-cert
Path to the TLS certificate for the admin API.
## api-key
Path to the TLS key for the admin API.
# ZONES
Each element of the
**zones**
list defines an authoritative zone.
## name
Zone name in fully qualified domain form.
## ns
List of authoritative nameservers; the parent zone must delegate to
these.
## admin
Administrator mailbox in dotted form.
## ttl_soa
TTL of the SOA record.
## ttl_answer
Default TTL for synthesized apex answers.
## refresh
SOA refresh interval in seconds.
## retry
SOA retry interval in seconds.
## expire
SOA expire time in seconds.
## minttl
SOA minimum/negative cache TTL in seconds.
## serve
Set to
**local**
to have the zone served from this instance.
# ADDRESS POOLS
The following lists control A and AAAA answers at the apex.
## a_master , aaaa_master
Primary address pool returned when healthy.  Items may be plain
addresses or objects with
**ip**
and optional
**reverse**
boolean to generate PTRs under
reverse_dir .
## a_standby , aaaa_standby
Used when the master pool is unhealthy.
## a_fallback , aaaa_fallback
Returned when master and standby pools are down.
## rfc_master
List of RFC1918 IPv4 ranges to advertise internally.
## a_master_private , aaaa_master_private
Internal‑only addresses for split‑horizon deployments.
## ula_master
IPv6 ULA prefixes served only to internal clients.
## alias
ALIAS‑style target used when no A or AAAA lists are present.

Example with IPv4, IPv6, DNS64 and private ranges:

zones:
- name: example.net.
a_master: ["203.0.113.10"]
aaaa_master: ["2001:db8::10"]
rfc_master: ["10.0.0.0/8"]
ula_master: ["fd00:1234::/48"]
dns64_prefix: "64:ff9b::"
# GEOGRAPHIC ROUTING
The optional
**geoip**
block enables country or continent based routing.  Keys mirror the
global GeoIP options:
## database
Path to a MaxMind style database.
## prefer_ecs
Trust EDNS Client Subnet data.
## prefer_field
Either
**country**
or
**registered_country .**
## cache_ttl_sec
TTL for the lookup cache.

Within a zone, a
**geo**
block may specify allow lists for
**master**
,
**standby**
and
**fallback**
pools using
**allow_countries**
or
**allow_continents .**
# HEALTH CHECKS
Each zone may contain a
**health**
object describing how endpoints are probed.
## kind
One of
**http**
,
**http3**
,
**tcp**
,
**udp**
or
**rawip .**
## expect
Substring or pattern expected in the response.

Per‑kind options include:
## http / http3
host_header ,
sni ,
path ,
**insecure_tls**
boolean.
## tcp
port ,
tls_enable ,
sni
and
**alpn .**
## udp
port ,
udp_payload_b64
and
**udp_expect_re .**
## rawip
**protocol**
number to send.
# DNS64
When
**dns64_prefix**
is configured, the server synthesises AAAA responses from A records in
zones lacking native IPv6. The IPv4 address is mapped into the prefix and
returned to the client, which then connects through a NAT64 gateway to
reach the IPv4-only endpoint.

IPv6 client -> AAAA? -> breathgslb DNS64 -> A? -> IPv4 host
<- AAAA  <-             <- A  <-
This enables IPv6-only networks to consume services that have not yet been
modernised for dual stack.
# DNSSEC
The optional
**dnssec**
block enables inline signing with:
## dnssec.mode
Selects the DNSSEC mode: `off`, `manual`, or `generated`.
## dnssec.zsk_keyfile , dnssec.ksk_keyfile
Paths to the ZSK and KSK key files or prefixes.
# TSIG
Global TSIG settings reside in the
**tsig**
block.  Secrets are generated on start if missing and, when
**tsig.path**
is set, written to that directory as
files.
## seed_env
Environment variable name used to deterministically derive secrets.
## default_algorithm
Default HMAC algorithm when not specified per key.
## keys
List of key objects containing
**name**
(owner form with trailing dot), optional
**algorithm**
,
**secret**
(leave empty to derive), and
**allow_xfr_from**
list of IPs permitted to perform AXFR.

Increase the optional
**epoch**
field to rotate a derived key.  For security, rotate TSIG keys at
least every 90 days.  When
**tsig.path**
is used, replace the key file atomically and update any dependent
symlinks before reloading the daemon.
# STATIC RECORDS
Zone blocks may include lists named
**txt**
,
**mx**
,
**caa**
,
**rp**
,
**sshfp**
,
**srv**
and
**naptr**
matching their respective DNS RR formats.  Each entry accepts a
**ttl**
in seconds.
# API
The admin API serves
**/health**
and
**/stats**
endpoints over HTTPS.  Generate an API token with a random tool such as
openssl rand -hex 16 ,
store it in a file, and reference it via
**api-token**
or the
**-api-token**
flag.  Certificates and keys may be produced with
openssl (1)
or a certificate authority.  Rotate TLS material by replacing the
underlying files and updating a stable symlink before reloading the
service.
# RFC1918 AND ULA
Private IPv4 ranges defined by RFC1918
(10/8, 172.16/12, 192.168/16) are never routed on the public Internet.
IPv6 uses Unique Local Addresses under
**fc00::/7**
(typically
**fd00::/8)**
for the same purpose. ULAs are globally unique when generated with a
random 40‑bit prefix yet remain local by policy. Use public addresses for
globally reachable services and reserve RFC1918/ULA space for internal
hosts.
# SPLIT HORIZON
For internal and external views run separate daemon instances with
different configuration files and listening addresses.  Provide
internal addresses in
**a_master_private**
and
**ula_master**
lists while keeping public addresses in
**a_master**
and
**aaaa_master .**
Place private or ULA addresses first so clients prefer local paths before
falling back to globals. Example:

a_master_private:
- 10.0.0.10
- 10.0.0.11
a_master:
- 203.0.113.10

ula_master:
- fd00:1::10
aaaa_master:
- 2001:db8::10

internal client -> resolver -> 10.0.0.10, 203.0.113.10
(prefers first, stays on LAN)
Shared TSIG keys allow signed transfers between views.
# FILES
## /etc/breathgslb/config.yaml
Typical configuration path.
## /etc/breathgslb/keys
Default directory for generated TSIG key files.
# SEE ALSO
breathgslb (8)```
