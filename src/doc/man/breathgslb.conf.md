# NAME
breathgslb.conf - configuration file for breathgslb

# DESCRIPTION

`breathgslb.conf` is a YAML configuration file. The daemon reads one main
config file and may also load forward zone files from `zones_dir` and reverse
zone files from `reverse_dir`.

The current runtime model supports:

- primary and secondary authoritative zones
- catalog-based secondary discovery
- DNSSEC with NSEC or NSEC3
- TSIG-authenticated transfer
- apex and host-level pools
- named-pool geographic routing
- lightup forward and reverse synthesis

The full narrative reference is in `src/doc/configuration.md`. This manpage is
the concise field reference.

# GLOBAL KEYS

## listen

Fallback bind address, usually `:53`.

## listen_addrs

Explicit `host:port` bind targets. Highest precedence.

## interfaces

Interface names whose addresses are used for binding when `listen_addrs` is not
set.

## zones_dir

Directory containing forward zone files named `*.fwd.yaml`.

## reverse_dir

Directory containing reverse zone files named `*.rev.yaml`.

## timeout_sec, interval_sec, rise, fall, jitter_ms, cooldown_sec

Health-check and reload timing controls.

## dns64_prefix

IPv6 prefix used when synthesising AAAA from A.

## edns_buf

Advertised EDNS UDP payload size.

## max_records

Maximum A/AAAA records per answer.

## log_queries, log_file, log_syslog

Logging controls.

## tsig.path

Directory where TSIG key files are written and reused.

## geoip

GeoIP lookup settings:

- `enabled`
- `database`
- `prefer_field`
- `cache_ttl_sec`

`prefer_field` controls whether the daemon prefers MaxMind
`registered_country` or `country`.

## discovery

Shared catalog bootstrap for config-only secondaries:

- `catalog_zone`
- `masters`
- `xfr_source`
- `ttl`
- `tsig`

# ZONES

Each `zones` element defines one authoritative zone.

## Core fields

- `name`
- `ns`
- `admin`
- `ttl_soa`
- `ttl_answer`
- `refresh`
- `retry`
- `expire`
- `minttl`

## serve

Zone role:

- omitted or `primary` for local authoritative zones
- `local` for local/private view behavior
- `secondary` for replicated zones

## masters

Master servers for a `secondary` zone.

## xfr_source

Optional source IP for outbound AXFR/IXFR. Only use this when that IP is
actually configured on the local host.

# APEX ADDRESS MODELS

BreathGSLB currently understands both:

- legacy apex fields such as `a_master`, `aaaa_master`, `a_standby`,
  `aaaa_standby`, `a_fallback`, `aaaa_fallback`
- the current `pools` model

Legacy private/local fields also remain supported:

- `a_master_private`, `aaaa_master_private`
- `a_standby_private`, `aaaa_standby_private`
- `a_fallback_private`, `aaaa_fallback_private`
- `rfc_master`, `ula_master`
- `rfc_standby`, `ula_standby`
- `rfc_fallback`, `ula_fallback`

Address items may be plain IP strings or objects with:

- `ip`
- optional `reverse: true`

# POOLS

`pools` define answer groups for the apex or for named hosts.

Each pool may contain:

- `name`
- `family` (`ipv4` or `ipv6`)
- `class` (`public` or `private`)
- `role` (`primary`, `secondary`, `fallback`, or another operator-defined name)
- `members`
- `client_nets`

`members` are the returned IPs. `client_nets` restrict private pools to
specific source CIDRs.

# HOSTS

`hosts` define first-class in-zone `A` and `AAAA` answers below the apex.

Each host may contain:

- `name`
- `alias`
- `pools`
- `geo`
- `health`

This is the supported way to create steerable non-apex host addresses inside
the zone.

# GEOGRAPHIC ROUTING

`geo` matches against MaxMind ISO-style country and continent codes.

Named-pool geo is the preferred model:

```yaml
geo:
  eu-v6:
    allow_countries: ["GB", "FR", "DE"]
    allow_continents: ["EU"]
  us-v6:
    allow_countries: ["US", "CA"]
    allow_continents: ["NA"]
```

Legacy `master`, `standby`, and `fallback` geo policy is still supported.

`geo_answers` is separate from `geo`: it directly overrides returned answers by
country or continent.

# HEALTH

`health` may be defined at zone level or host level.

Supported kinds:

- `http`
- `http3`
- `tcp`
- `udp`
- `icmp`
- `rawip`

Common HTTP-style fields:

- `host_header`
- `path`
- `scheme`
- `method`
- `port`
- `expect`
- `sni`
- `insecure_tls`

The current inheritance model is:

- host `health` overrides zone `health`

# LIGHTUP

`lightup` provides deterministic forward and reverse synthesis inside configured
prefixes.

Supported fields include:

- `enabled`
- `ttl`
- `forward`
- `reverse`
- `strategy`
- `forward_template`
- `ptr_template`
- `families`

Each family may define:

- `family`
- `class`
- `prefix`
- `respond_a`
- `respond_aaaa`
- `respond_ptr`
- `exclude`

If `forward_template` is set, only names matching that exact template
synthesise forward answers. Exact template names are parsed back into the
embedded address and must fall inside the configured prefix and outside all
`exclude` ranges.

# REVERSE ZONES

Reverse zones may be:

- explicitly configured in `*.rev.yaml` files under `reverse_dir`
- generated from address objects that set `reverse: true`

Delegated reverse zones are served live and can be signed and transferred like
forward zones.

# DNSSEC

`dnssec` supports:

- `mode`: `off`, `manual`, `generated`
- `zsk_keyfile`
- `ksk_keyfile`
- `nsec3_iterations`
- `nsec3_salt`
- `nsec3_optout`

`nsec3_iterations: 0` means plain NSEC.

# TSIG

Per-zone `tsig` and shared `discovery.tsig` support:

- `default_algorithm`
- `seed_env`
- `epoch`
- `allow_unsigned`
- `keys`

Each key may contain:

- `name`
- `algorithm`
- `secret`
- `allow_xfr_from`

`allow_xfr_from` accepts exact IPs and IPv4 or IPv6 CIDRs.

# STATIC RECORD SECTIONS

The following record sections are supported:

- `txt`
- `mx`
- `caa`
- `rp`
- `sshfp`
- `srv`
- `naptr`
- `ptr`

# ALIAS AND CNAME

BreathGSLB supports ALIAS-style behavior through:

- `alias` at the apex
- `alias_host` for named subdomains
- `hosts[].alias` for first-class host entries

There is currently no first-class `cname:` section in the zone YAML model.

# SECONDARY SNAPSHOTS

Persisted `serve: secondary` zone files are local runtime snapshots for restart
durability. They are not operator-authored primary configs and should not be
copied blindly between nodes.
