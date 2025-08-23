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
# DNSSEC
The optional
**dnssec**
block enables inline signing with:
## dnssec.enable
Enable signing.
## dnssec.zsk_keyfile , dnssec.ksk_keyfile
Paths to the ZSK and KSK PEM files.
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
Shared TSIG keys allow signed transfers between views.
# FILES
## /etc/breathgslb/config.yaml
Typical configuration path.
## /etc/breathgslb/keys
Default directory for generated TSIG key files.
# SEE ALSO
breathgslb (8)