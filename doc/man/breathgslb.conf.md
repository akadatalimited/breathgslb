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
breathgslb (8)