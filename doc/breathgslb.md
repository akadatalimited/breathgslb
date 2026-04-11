# BreathGSLB Book

## Intro & Scope

BreathGSLB is an authoritative DNS server with:

- health-aware answer selection
- pools for apex and named hosts
- GeoIP steering
- lightup forward and reverse synthesis
- DNSSEC signing
- primary/secondary replication with discovery bootstrap

This book collates the man pages and longer-form reference material used to
build the PDF manual. The detailed configuration reference is generated from
the current `breathgslb.conf(5)` source and reflects the live runtime model.

## Runtime Model

The current model is:

- one main config for listeners, timing, GeoIP, TSIG, and discovery
- forward zone files in `zones_dir`
- reverse zone files in `reverse_dir`
- primary zones and discovery-based secondaries
- apex and named hosts answered through the same pool model

BreathGSLB is authoritative only. It does not recurse.

## Config Model

The important design change is that the server is no longer just an
apex-steering engine.

It now supports:

- apex `pools`
- named `hosts`
- per-host `pools`
- named-pool `geo`
- zone-default `health` with host override
- deterministic `lightup`

Legacy `a_master` / `aaaa_master` and related fields still exist for
compatibility, but pools are the forward direction.

## Reverse, Lightup, and DNSSEC

Reverse zones are first-class data under `reverse_dir`, using `*.rev.yaml`.

`lightup` provides deterministic forward and reverse synthesis inside owned
prefixes. Exact template-shaped forward names return the embedded address if it
is valid for the configured family and not excluded. Reverse PTR generation
follows the configured templates so forward and reverse naming remain symmetric.

DNSSEC supports generated or manual keys, NSEC or NSEC3, and signed primary and
secondary answers.

## Replication

Secondaries may:

- bootstrap from a shared discovery catalog
- transfer zones with TSIG
- persist node-local secondary snapshots

Those persisted snapshots are runtime state, not shared source config. Shared
cluster material is limited to things such as TSIG and DNSSEC keys.

## Service Setup

Service definitions for common init systems are under `services/`. Use the
systemd unit on Linux distributions with systemd, the OpenRC script for Alpine
and other OpenRC systems, and the Launchd plist for macOS.

## Documentation Structure

The chapters below are generated from the current manpage sources.

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
instances when signed zone transfers are required.  Transfers signed with a
TSIG key are honored only from client addresses listed in that key's
fBallow_xfr_fromfP list; other sources receive fBREFUSEDfP.

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
breathgslb.conf - configuration format for BreathGSLB

# SYNOPSIS
**/etc/breathgslb/config.yaml**
**/etc/breathgslb/zones/*.fwd.yaml**
**/etc/breathgslb/reverse/*.rev.yaml**

# DESCRIPTION
BreathGSLB is configured from one main YAML file plus optional forward and
reverse zone files loaded from
**zones_dir**
and
reverse_dir .

The current model is:
one main config for listeners, timing, GeoIP, TSIG, API, and discovery
forward zones in
**zones_dir**
as
***.fwd.yaml**
reverse zones in
**reverse_dir**
as
***.rev.yaml**
primary or discovery-based secondary operation
apex and named hosts answered through the same pool model

BreathGSLB is authoritative only. It does not recurse.

# RUNTIME MODEL
At query time, resolution is layered in this order:
exact host match in
**hosts:**
host
**alias**
or zone
**alias_host**
**lightup**
synthesis for matching names
apex
**pools**
or legacy apex fields
static records such as
TXT ,
MX ,
CAA ,
RP ,
SSHFP ,
SRV ,
NAPTR ,
and
PTR

For a discovery-based secondary:
load only the main config
transfer the shared catalog zone
reconstruct full zone intent from the catalog payload
AXFR the discovered zones
persist local secondary snapshots for restart durability

# GLOBAL SETTINGS
Common top-level keys include:
## listen
Fallback bind address, usually
:53 .
## listen_addrs
Explicit bind addresses in
**host:port**
form.
## interfaces
Derive bind addresses from named interfaces.
## zones_dir
Directory containing forward zone files.
## reverse_dir
Directory containing reverse zone files.
## timeout_sec
Probe and transfer timeout base.
## interval_sec
Base interval between health rounds and runtime refresh cycles.
## rise
Successes required before a health state becomes UP.
## fall
Failures required before a health state becomes DOWN.
## jitter_ms
Random delay added to probe scheduling.
## cooldown_sec
Minimum dwell time before a tier or pool flips state.
## dns64_prefix
Prefix used for synthetic AAAA from A.
## edns_buf
Advertised EDNS UDP payload size.
## max_records
Maximum A or AAAA records returned in one answer.
## log_queries
Enable query logging.
## log_file
Log file path.
## log_syslog
Enable syslog logging.
## tsig.path
Directory used for TSIG key persistence.
## geoip
GeoIP enablement and MMDB configuration.
## discovery
Shared catalog bootstrap for config-only secondaries.

# DISCOVERY
The
**discovery**
block allows a secondary to start from only its main config.

discovery:
  catalog_zone: "_catalog.breathgslb."
  masters: ["[2a02:8012:bc57:53::1]:53"]
  xfr_source: "2a02:8012:bc57:53a::1"
  tsig:
    default_algorithm: "hmac-sha256"
    keys:
      - name: "lightitup-xfr."
        secret: ""

Fields:
## catalog_zone
Shared catalog zone used for bootstrap.
## masters
Primaries to query for that catalog.
## xfr_source
Optional local source IP for outbound AXFR. Only set this when that exact
address exists on the local host.
## tsig
Shared transfer/bootstrap key material.

# ZONES
Each zone entry defines one authoritative zone.

- name: "lightitup.zerodns.co.uk."
  ns: ["gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."]
  admin: "hostmaster.zerodns.co.uk."
  ttl_soa: 60
  ttl_answer: 20
  refresh: 60
  retry: 10
  expire: 90
  minttl: 60
  serve: "primary"

Important fields:
## name
Zone FQDN.
## ns
Published authoritative NS set.
## admin
SOA mailbox in dotted form.
## ttl_soa
SOA TTL.
## ttl_answer
Default TTL for dynamic A and AAAA answers.
## refresh
SOA refresh timer.
## retry
SOA retry timer.
## expire
SOA expire timer.
## minttl
SOA minimum TTL.
## serve
Zone role:
primary ,
local ,
or
secondary .
## masters
Upstream primaries for a secondary zone.
## xfr_source
Optional source IP used when the zone AXFRs from a master.

# APEX MODEL
There are two apex answer models:
legacy apex fields such as
a_master ,
aaaa_master ,
a_standby ,
aaaa_standby ,
a_fallback ,
and related private/local-view fields
the current
**pools**
model

Legacy fields remain for compatibility. Pools are the long-term direction.

# POOLS
Pools are the current answer-selection model for the apex and for named hosts.

pools:
  - name: "public-v6-primary"
    family: "ipv6"
    class: "public"
    role: "primary"
    members:
      - ip: "2a02:8012:bc57:5353::1"
  - name: "private-v4-primary"
    family: "ipv4"
    class: "private"
    role: "primary"
    members:
      - ip: "172.16.0.1"
    client_nets:
      - "172.16.0.0/24"

Pool fields:
## name
Stable pool identifier used by geo policy.
## family
Either
**ipv4**
or
ipv6 .
## class
Usually
**public**
or
private .
## role
Typically
primary ,
secondary ,
or
fallback .
## members
The actual IPs returned in DNS answers.
## client_nets
Source CIDRs that make a private pool eligible.

# HOSTS
**hosts:**
provides first-class in-zone names.

hosts:
  - name: "app"
    health:
      kind: http
      host_header: "app.lightitup.zerodns.co.uk"
      path: "/health"
    pools:
      - name: "app-v6"
        family: "ipv6"
        class: "public"
        role: "primary"
        members:
          - ip: "2a02:8012:bc57:5353::10"

Each host can carry:
**pools**
**geo**
**health**
**alias**

Zone health is the default. Host health overrides it when present.

# GEO ROUTING
Geo routing uses MaxMind country data from the configured MMDB.

The code reads:
**country.iso_code**
**registered_country.iso_code**
**continent.code**

Those ISO-style codes are matched directly against:
**allow_countries**
**allow_continents**

Named-pool geo is the preferred model:

geo:
  eu-v6:
    allow_countries: ["GB", "FR", "DE"]
    allow_continents: ["EU"]
  us-v6:
    allow_countries: ["US", "CA"]
    allow_continents: ["NA"]
  global-v6:
    allow_all: true

Legacy
geo.master ,
geo.standby ,
and
**geo.fallback**
still work for older configs.

**geo_answers**
is separate from
geo .
It directly overrides returned answers by country or continent.

# LIGHTUP
**lightup**
provides deterministic forward and reverse synthesis inside configured owned
prefixes.

lightup:
  enabled: true
  forward_template: "fresh-{addr}.lightitup.zerodns.co.uk."
  families:
    - family: "ipv6"
      class: "public"
      prefix: "2a02:8012:bc57:5353::/64"
      respond_aaaa: true
      respond_ptr: true
      exclude:
        - "2a02:8012:bc57:5353::1/128"

Purpose:
synthetic forward names for addresses you own
deterministic PTR generation
stable forward/reverse round-tripping

Important behavior:
explicit records always win
with an explicit
**forward_template**
only names matching that template synthesize
excluded ranges are hard deny-ranges inside the lightup prefix
exact template names return the embedded address if it is inside the configured
prefix and not excluded

# REVERSE ZONES
Delegated reverse zones are first-class YAML files in
reverse_dir .
Files use the
***.rev.yaml**
suffix.

Reverse zones may contain:
explicit PTR records
generated PTR data requested by
**reverse: true**
on configured addresses
lightup synthetic PTRs for owned prefixes

# DNSSEC
DNSSEC supports:
manual or generated key material
plain NSEC or NSEC3
signed primary answers
signed secondary answers using transferred signed data

For generated keys, use stable key paths under
/etc/breathgslb/keys/ .

# TRANSFERS AND TSIG
Per-zone
**tsig**
and shared
**discovery.tsig**
support signed zone transfers.

**allow_xfr_from**
accepts:
exact IPv4 addresses
exact IPv6 addresses
IPv4 CIDRs
IPv6 CIDRs

Use
**xfr_source**
only when the chosen source IP is actually configured on the local host.

# ALIAS, CNAME, AND OTHER RECORDS
The current schema supports:
zone apex
**alias**
host
**alias**
map-based host ALIAS through
**alias_host**
named host
**A**
and
**AAAA**
through
**hosts**
and
**pools**
static
TXT ,
MX ,
CAA ,
RP ,
SSHFP ,
SRV ,
NAPTR ,
and
PTR

There is not currently a first-class
**cname**
section in the zone schema.

Use:
**hosts**
for real in-zone
**A**
and
**AAAA**
**alias**
or
**alias_host**
for ALIAS-style behavior
**lightup**
for deterministic synthetic names

# FILES
## /etc/breathgslb/config.yaml
Main config.
## /etc/breathgslb/zones/
Forward zone files.
## /etc/breathgslb/reverse/
Reverse zone files.
## /etc/breathgslb/keys/
DNSSEC key material.
## /etc/breathgslb/tsig/
TSIG key material.
## /etc/breathgslb/serials/
Persisted SOA serial state.

# SEE ALSO
breathgslb (8)```
