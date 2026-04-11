# Configuration

BreathGSLB is configured from one main YAML file plus optional zone files loaded
from `zones_dir` and `reverse_dir`.

Typical invocation:

```sh
breathgslb -config /etc/breathgslb/config.yaml
```

The current model is:

- one main config for listeners, probe timing, TSIG, GeoIP, and discovery
- one or more forward zone files in `zones_dir` as `*.fwd.yaml`
- one or more reverse zone files in `reverse_dir` as `*.rev.yaml`
- optional generated or persisted secondary snapshots under the same tree

This document is the operator-facing source of truth for the current runtime
model: discovery, primary/secondary replication, apex pools, host pools, geo,
lightup, reverse zones, DNSSEC, and supported record sections.

## Runtime Model

BreathGSLB answers authoritatively only. It does not recurse.

At query time, resolution is layered in this order:

1. explicit host policy (`hosts:` exact-name matches)
2. host `alias` or zone `alias_host`
3. lightup synthesis for matching names
4. apex pools or legacy apex fields
5. static records such as TXT, MX, CAA, RP, SSHFP, SRV, NAPTR, PTR

For a discovery-based secondary:

1. the secondary loads only its main config
2. it AXFRs the shared catalog zone
3. it bootstraps full secondary zone intent from that catalog payload
4. it AXFRs each discovered zone from its primary
5. it persists local secondary snapshots for restart durability

## Global Settings

| Key | Type | What it does | Why it exists |
| --- | --- | --- | --- |
| `listen` | string | Fallback bind address, usually `:53` | Simple default when you do not pin interfaces or addresses |
| `listen_addrs` | list[string] | Explicit `host:port` bind targets | Deterministic binding on multi-address systems |
| `interfaces` | list[string] | Derive bind addresses from named interfaces | Useful on routed IPv6 hosts where addresses live on specific interfaces |
| `zones_dir` | string | Auto-load forward zone files from this directory | Keeps main config small and zone files separate |
| `reverse_dir` | string | Auto-load reverse zone files from this directory | Lets delegated reverse zones be managed as first-class data |
| `timeout_sec` | int | Probe and transfer timeout base | Keeps health and AXFR failure detection bounded |
| `interval_sec` | int | Base interval between health rounds and runtime refresh cycles | Drives how quickly health and live file/discovery updates are seen |
| `rise` | int | Successes required before a tier is UP | Dampens flaps |
| `fall` | int | Failures required before a tier is DOWN | Dampens flaps |
| `jitter_ms` | int | Random delay added to probe scheduling | Prevents lockstep probe bursts |
| `cooldown_sec` | int | Minimum dwell time before state flips | Avoids rapid oscillation |
| `dns64_prefix` | string | Prefix for synthetic AAAA from A | Allows IPv6-only clients to reach IPv4-only answers |
| `edns_buf` | int | Advertised EDNS UDP payload size | Keeps answers under a safe transport size |
| `max_records` | int | Max A/AAAA records per answer | Prevents oversized RRsets |
| `log_queries` | bool | Query logging | Useful for operator debugging |
| `log_file` | string | File logger target | Persistent runtime logging |
| `log_syslog` | bool | Syslog logging | Integrates with host logging stack |
| `max_workers` | int | UDP listener worker count | Throughput tuning |
| `tsig.path` | string | Directory for TSIG key files | Stable transfer key persistence |
| `geoip.enabled` | bool | Enable GeoIP lookups | Turns on geo policy and geo answer selection |
| `geoip.database` | string | Path to MaxMind country DB | Source of country and continent codes |
| `geoip.prefer_field` | string | `country` or `registered`/`registered_country` | Chooses which MMDB country field drives policy |
| `geoip.cache_ttl_sec` | int | Geo lookup cache TTL | Avoids repeated MMDB hits |
| `api`, `api-listen`, `api-interface`, `api-token`, `api-cert`, `api-key` | mixed | HTTPS admin API settings | Optional runtime control and visibility |
| `discovery` | mapping | Shared catalog bootstrap for secondaries | Lets secondaries start from only the main config |

Binding precedence is:

1. `listen_addrs`
2. `interfaces`
3. `listen`
4. default `:53`

## Discovery

The `discovery` block is how a config-only secondary finds zones without
shipping local forward/reverse YAML for every zone.

```yaml
discovery:
  catalog_zone: "_catalog.breathgslb."
  masters: ["[2a02:8012:bc57:53::1]:53"]
  xfr_source: "2a02:8012:bc57:53a::1"
  tsig:
    default_algorithm: "hmac-sha256"
    keys:
      - name: "lightitup-xfr."
        secret: ""
```

Fields:

- `catalog_zone`: shared catalog zone name used for bootstrap
- `masters`: primaries to query for that catalog
- `xfr_source`: optional local source IP for outbound AXFR; only set this when
  that address is actually configured on the local host
- `tsig`: shared transfer/bootstrap key material

Why it works this way:

- AXFR only transfers RRsets, not full policy intent
- the catalog therefore also carries a protected zone-policy payload
- a discovery-based secondary reconstructs the rich zone model before normal
  zone transfer begins

## Zones

Each `zones` item defines one authoritative zone.

```yaml
- name: "lightitup.zerodns.co.uk."
  ns: ["gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."]
  admin: "hostmaster.zerodns.co.uk."
  ttl_soa: 60
  ttl_answer: 20
  refresh: 60
  retry: 10
  expire: 90
  minttl: 60
```

Common fields:

| Key | What it does |
| --- | --- |
| `name` | Zone FQDN |
| `ns` | Authoritative NS set published at the zone apex |
| `admin` | SOA mailbox in dotted form |
| `ttl_soa` | SOA TTL |
| `ttl_answer` | Default TTL for dynamic A/AAAA answers |
| `refresh`, `retry`, `expire`, `minttl` | SOA timers |
| `serve` | Zone mode |
| `masters` | Upstream primaries for a `secondary` zone |
| `xfr_source` | Optional source IP used when the zone AXFRs from a master |

### Zone Roles

`serve` currently has three practical modes:

- omitted or `"primary"`: the zone is locally authoritative
- `"local"`: the zone is locally authoritative and enables private/public local
  view behavior
- `"secondary"`: the zone is a replica and must pull from `masters`

`serve: "secondary"` is required in local persisted secondary snapshots so the
daemon can reload them safely as replicas instead of treating them as primaries.

## Apex Answers

There are two apex configuration models:

1. legacy apex fields
2. the current pool model

The pool model is the long-term direction. Legacy fields remain for
compatibility and are still understood by the runtime.

### Legacy Apex Fields

Legacy apex fields define public and private answers by tier:

- `a_master`, `aaaa_master`
- `a_standby`, `aaaa_standby`
- `a_fallback`, `aaaa_fallback`
- `a_master_private`, `aaaa_master_private`
- `a_standby_private`, `aaaa_standby_private`
- `a_fallback_private`, `aaaa_fallback_private`
- `rfc_master`, `ula_master`
- `rfc_standby`, `ula_standby`
- `rfc_fallback`, `ula_fallback`

Each address item may be:

- a scalar IP string
- or an object with `ip` and optional `reverse: true`

`reverse: true` requests generated PTR data for that address.

### Pools

Pools are the current answer-selection model for the apex and for named hosts.

```yaml
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
```

Pool fields:

| Key | What it means |
| --- | --- |
| `name` | Stable pool identifier used by geo policy |
| `family` | `ipv4` or `ipv6` |
| `class` | `public` or `private` |
| `role` | Usually `primary`, `secondary`, or `fallback` |
| `members` | The actual IPs returned in DNS answers |
| `client_nets` | Source CIDRs that make a private pool eligible |

Why pools exist:

- one host can have many candidate addresses
- public/private answers can be expressed cleanly
- geo can prefer named pools instead of hard-coded tier labels
- the same model works for apex and non-apex hosts

## Hosts

`hosts:` creates first-class in-zone hostnames with their own `A`/`AAAA`
behavior. This is how non-apex host addresses are defined today.

```yaml
hosts:
  - name: "app"
    health:
      kind: http
      host_header: "app.lightitup.zerodns.co.uk"
      path: "/health"
      scheme: https
      method: GET
      port: 443
      expect: "OK"
    pools:
      - name: "app-v6-primary"
        family: "ipv6"
        class: "public"
        role: "primary"
        members:
          - ip: "2a02:8012:bc57:5353::10"
      - name: "app-v4-private"
        family: "ipv4"
        class: "private"
        role: "primary"
        members:
          - ip: "172.16.0.10"
        client_nets:
          - "172.16.0.0/24"
```

Important behavior:

- `hosts[].name` is an exact owner name relative to the zone
- host answers are exact-name only; there is no wildcard host config
- host `health` overrides zone `health`
- host `geo` overrides zone `geo` for that host
- host `alias` is supported

Current health inheritance is:

1. host `health`, if present
2. zone `health`

Pool-level and member-level health overrides are not yet part of the runtime
model.

## Geo Routing

Geo policy uses the MaxMind country database and exact uppercase code matching.

```yaml
geo:
  public-v6-primary:
    allow_countries: ["GB", "FR", "DE"]
    allow_continents: ["EU"]
  public-v6-secondary:
    allow_countries: ["US", "CA"]
    allow_continents: ["NA"]
  public-v6-fallback:
    allow_all: true
```

How it works:

1. client IP or ECS subnet is looked up in the MMDB
2. the resolver reads:
   - `country.iso_code`
   - optionally `registered_country.iso_code`
   - `continent.code`
3. these become uppercase strings such as `GB`, `US`, `EU`, `NA`
4. pool or tier policy is matched by exact code membership

`allow_countries` and `allow_continents` must therefore use ISO-style codes
from the MMDB. Typical examples:

- countries: `GB`, `FR`, `DE`, `US`, `CA`
- continents: `EU`, `NA`, `OC`, `AS`

Legacy `geo.master`, `geo.standby`, and `geo.fallback` still work. Named-pool
geo is the preferred model when `pools:` are present.

`geo_answers` is separate from `geo`. It does not just select an eligible pool;
it directly overrides returned A/AAAA/private answers by country or continent.

## Health Checks

`health` defines how BreathGSLB decides whether `primary` or `secondary` style
pools are healthy enough to serve.

Supported kinds:

- `http`
- `http3`
- `tcp`
- `udp`
- `icmp`
- `rawip`

Common fields:

- `kind`
- `expect`

HTTP/HTTP3 fields:

- `host_header`
- `path`
- `scheme`
- `method`
- `port`
- `sni`
- `insecure_tls`

TCP fields:

- `port`
- `tls_enable`
- `sni`
- `alpn`

UDP fields:

- `port`
- `udp_payload_b64`
- `udp_expect_re`

RAWIP fields:

- `protocol`

Why health exists:

- `primary` and `secondary` pools should not be served blindly
- A and AAAA families can fail independently
- rise/fall/cooldown avoid unstable DNS behavior during blips

## Lightup

`lightup` is deterministic forward and reverse synthesis inside configured test
or service prefixes. It is how BreathGSLB creates many in-zone names and PTRs
without hand-writing every RR.

```yaml
lightup:
  enabled: true
  ttl: 60
  forward: true
  reverse: true
  strategy: "hash"
  forward_template: "templated-{addr}.lightitup.zerodns.co.uk."
  ptr_template: "ptr-{addr}.lightitup.zerodns.co.uk."
  families:
    - family: "ipv6"
      class: "public"
      prefix: "2a02:8012:bc57:5353::/64"
      respond_aaaa: true
      respond_ptr: true
      exclude:
        - "2a02:8012:bc57:5353::1/128"
```

Fields:

| Key | What it does |
| --- | --- |
| `enabled` | Turns the feature on |
| `ttl` | TTL for synthetic records |
| `forward` | Enable forward synthetic `A`/`AAAA` |
| `reverse` | Enable synthetic PTR |
| `strategy` | Current strategy name; non-template names use deterministic synthesis |
| `forward_template` | Exact name pattern used for forward template parsing |
| `ptr_template` | Optional PTR target pattern; if unset, `forward_template` is reused |
| `families` | Per-family prefix/class behavior |

Family fields:

- `family`: `ipv4` or `ipv6`
- `class`: `public` or `private`
- `prefix`: the routable or private space lightup owns
- `respond_a`, `respond_aaaa`, `respond_ptr`
- `exclude`: CIDRs inside that prefix that must never synthesize

### What exclusions do

Exclusions are hard deny-ranges inside the lightup prefix. They exist so you
can reserve real service addresses, routers, nameserver IPs, and manually
managed endpoints while still synthesizing the rest of the space.

If an address is excluded:

- reverse PTR synthesis refuses it
- exact forward template parsing refuses it
- no hash fallback is used for that exact template name

### Forward template format

When `forward_template` contains `{addr}`, BreathGSLB can parse the embedded
address back out of the name.

Examples:

- IPv6: `templated-2a02-8012-bc57-5353-0000-0000-abc1-abc1.lightitup.zerodns.co.uk.`
- IPv4: `templated-172-16-0-42.lightitup.zerodns.co.uk.`

If a `forward_template` is configured:

- only names matching that exact template synthesize
- arbitrary names such as `trash.lightitup.zerodns.co.uk.` return `NXDOMAIN`
- exact template names return the embedded address if it is inside the lightup
  prefix and not excluded

This is how forward/reverse symmetry works:

1. `dig -x <ip>` returns a templated PTR name
2. `dig AAAA/A <templated-name>` returns that exact original IP

### PTR template format

`ptr_template` controls how synthetic PTR targets are named.

If `ptr_template` is unset, BreathGSLB reuses `forward_template` so reverse and
forward naming stay symmetric automatically.

## Reverse Zones

Reverse zones can be provided in two ways:

1. explicit reverse zone files under `reverse_dir`
2. generated reverse data from `reverse: true` on address objects

Explicit reverse zone files are normal zone definitions loaded from
`*.rev.yaml`, for example:

```yaml
- name: "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa."
  serve: "primary"
  ptr:
    - name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
      ptr: "gslb.zerodns.co.uk."
```

Why explicit reverse zones matter:

- delegated reverse space is independent DNS authority
- reverse zones must be served live, not just generated at config time
- DNSSEC and AXFR must treat reverse zones exactly like forward zones

For IPv6 reverse lookups, owner names are full nibble-form labels under the
delegated `ip6.arpa.` zone.

## DNSSEC

`dnssec` controls inline signing.

```yaml
dnssec:
  mode: generated
  zsk_keyfile: "/etc/breathgslb/keys/lightitup.zerodns.co.uk.zsk"
  ksk_keyfile: "/etc/breathgslb/keys/lightitup.zerodns.co.uk.ksk"
  nsec3_iterations: 0
```

Fields:

- `mode`: `off`, `manual`, or `generated`
- `zsk_keyfile`, `ksk_keyfile`: key prefixes
- `nsec3_iterations`, `nsec3_salt`, `nsec3_optout`

Behavior:

- `generated` creates and reuses persisted keys automatically
- `nsec3_iterations: 0` means plain NSEC
- `nsec3_iterations > 0` enables NSEC3

## TSIG and Transfers

Zone transfer auth is controlled by per-zone `tsig` and optional shared
`discovery.tsig`.

```yaml
tsig:
  default_algorithm: "hmac-sha256"
  keys:
    - name: "lightitup-xfr."
      secret: ""
      allow_xfr_from:
        - "2a02:8012:bc57::/48"
```

Fields:

- `default_algorithm`
- `seed_env`
- `epoch`
- `allow_unsigned`
- `keys[].name`
- `keys[].algorithm`
- `keys[].secret`
- `keys[].allow_xfr_from`

`allow_xfr_from` accepts:

- exact IPv4 or IPv6 addresses
- IPv4 CIDRs
- IPv6 CIDRs such as `/64` or `/48`

Why `xfr_source` exists:

- a multi-address secondary may need to force AXFR to come from its NS address
- some primaries enforce ACLs on that source

Do not set `xfr_source` unless that exact IP is configured on the local host.

## Static Record Sections

These sections are authoritative data published exactly as configured:

- `txt`
- `mx`
- `caa`
- `rp`
- `sshfp`
- `srv`
- `naptr`
- `ptr`

They are available at the apex or at specific names through their `name` field.

## Hostname Records Inside a Zone

Current support for names below the apex:

- exact-name `A`/`AAAA`: `hosts[].pools`
- host ALIAS: `hosts[].alias`
- map-based host ALIAS: `alias_host`
- synthetic host `A`/`AAAA`/`PTR`: `lightup`
- static TXT/MX/CAA/RP/SSHFP/SRV/NAPTR/PTR: record sections with explicit names

Important current limitation:

- there is no first-class `cname:` record section
- there is no raw arbitrary static `A:` or `AAAA:` list outside `hosts[].pools`

So if you need a hostname inside the zone:

- use `hosts:` with `pools:` for first-class steerable `A`/`AAAA`
- use `alias_host` or `hosts[].alias` for ALIAS-style behavior
- use `lightup` for deterministic synthetic names

## Secondary Snapshots

Persisted secondary YAML files are local runtime state. They are written so a
secondary can restart without losing transferred intent.

They are not hand-authored primary config files, and they should not be copied
blindly between hosts.

Shared between nodes:

- `/etc/breathgslb/keys/`
- `/etc/breathgslb/tsig/`

Node-local runtime state:

- persisted `serve: "secondary"` snapshots
- local serial files

## Example Layout

```yaml
listen_addrs:
  - "[2a02:8012:bc57:53::1]:53"
zones_dir: "/etc/breathgslb/zones"
reverse_dir: "/etc/breathgslb/reverse"

discovery:
  catalog_zone: "_catalog.breathgslb."
  masters: ["[2a02:8012:bc57:53::1]:53"]
  xfr_source: "2a02:8012:bc57:53a::1"

tsig:
  path: "/etc/breathgslb/tsig"

geoip:
  enabled: true
  database: "/etc/breathgslb/geoip/GeoLite2-Country.mmdb"
  prefer_field: "registered"
  cache_ttl_sec: 600
```
