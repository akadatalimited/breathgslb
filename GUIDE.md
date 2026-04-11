# BreathGSLB Guide

This guide is the short operator/developer orientation. The detailed config
reference is:

- [Configuration](src/doc/configuration.md)

The current design documents are:

- [POOLS](POOLS.md)
- [Zone Replication](ZONE_REPLICATION.md)
- [Lightup Plan](LIGHTITUP.md)

## Runtime Model

BreathGSLB is authoritative only.

It is configured from:

- one main config
- forward zone files in `zones_dir`
- reverse zone files in `reverse_dir`
- local key, TSIG, and serial state under `/etc/breathgslb`

Resolution order is:

1. exact host match in `hosts:`
2. host `alias` or zone `alias_host`
3. lightup synthesis
4. apex pools or legacy apex fields
5. static records

For a discovery-based secondary:

1. load main config only
2. transfer the shared catalog zone
3. reconstruct full zone intent from the catalog payload
4. AXFR each discovered zone
5. persist node-local secondary snapshots

## Zone Model

The current model is no longer apex-only.

There are now three layers:

- zone defaults
- apex pools
- named hosts with their own pools

That means:

- the apex can answer through `pools:`
- named hosts such as `app.example.net.` can also answer through `hosts:`
- legacy `a_master` / `aaaa_master` style fields still work, but are
  compatibility input

## Pools

Pools are the current answer-selection unit.

A pool contains:

- `name`
- `family`
- `class`
- `role`
- `members`
- optional `client_nets`

Why pools exist:

- one host may have many candidate IPs
- public and private answers need separate eligibility
- geo routing wants to select named answer groups
- the same model should work for apex and non-apex hosts

Current direction:

- use pools for new configs
- keep legacy apex fields as compatibility only

## Hosts

`hosts:` provides first-class in-zone names.

Example intent:

- `name: "@"` for the apex
- `name: "app"` for `app.zone.`
- `name: "api"` for `api.zone.`

Each host can carry:

- `pools`
- `geo`
- `health`
- `alias`

Current health inheritance is:

1. host `health`
2. otherwise zone `health`

Pool/member health overrides are intentionally not in use yet.

## Geo Routing

Geo routing is driven by MaxMind MMDB country data.

The code reads:

- `country.iso_code`
- `registered_country.iso_code`
- `continent.code`

Then it compares those ISO codes directly against config:

- `allow_countries`
- `allow_continents`

Current preferred geo model is named-pool geo, for example:

```yaml
geo:
  eu-v6:
    allow_countries: ["GB", "FR", "DE"]
    allow_continents: ["EU"]
  us-v6:
    allow_countries: ["US", "CA"]
    allow_continents: ["NA"]
  fallback-v6:
    allow_all: true
```

Legacy `geo.master`, `geo.standby`, and `geo.fallback` still exist for older
configs.

`geo_answers` is separate. It does direct answer override, not just pool
selection.

## Lightup

`lightup` is deterministic synthesis for owned address space.

It is for:

- synthetic forward names
- synthetic reverse PTRs
- round-trip naming in test or internal address space

Current behavior:

- explicit records always win
- exact-template forward names return the embedded IP
- exclusions deny synthesis inside the owned prefix
- arbitrary names only synthesize when the config allows it
- with an explicit `forward_template`, only matching names synthesize

Lightup supports:

- IPv6 public families
- IPv6 private families
- IPv4 private families

## Reverse Zones

Reverse zones are first-class YAML in `reverse_dir`.

They may contain:

- explicit PTRs
- generated PTRs requested by `reverse: true`
- lightup synthetic PTRs for owned prefixes

Files use:

- `*.rev.yaml`

Delegated reverse zones should be served directly from `reverse_dir`.

## DNSSEC

Current DNSSEC behavior:

- generated or manual keys
- plain NSEC or NSEC3
- signed primary answers
- signed secondary answers using transferred signed data
- query-aware denial logic so NSEC/NSEC3 matches what is actually served

Generated key mode persists keys on disk. The same zone keys must exist on
every node that is expected to serve the same signed zone data.

## Replication

Primary/secondary replication now supports:

- TSIG-protected AXFR
- discovery bootstrap
- `xfr_source`
- IPv4 and IPv6 `allow_xfr_from` CIDRs
- persisted local secondary snapshots

Important boundary:

- shared material between nodes is keys and TSIG
- persisted `serve: secondary` snapshots are node-local runtime state
- do not blindly copy one node’s secondary snapshots onto another host

## Records Inside a Zone

The current options are:

- apex `A` / `AAAA` through pools or legacy apex fields
- host `A` / `AAAA` through `hosts:` plus `pools:`
- host and apex ALIAS behavior through `alias`, `hosts[].alias`, and
  `alias_host`
- static `TXT`, `MX`, `CAA`, `RP`, `SSHFP`, `SRV`, `NAPTR`, `PTR`

There is not currently a first-class `cname:` section.

Use:

- `hosts:` for real in-zone `A` / `AAAA`
- `alias` / `alias_host` for ALIAS-style behavior
- `lightup` for deterministic synthetic names

## Operations

Build:

```sh
make build
```

Run:

```sh
./breathgslb -config /etc/breathgslb/config.yaml
```

Reload:

```sh
kill -HUP "$(pidof breathgslb)"
```

Tests:

```sh
make test
go -C src test -run TestName ./...
```

Live demo:

- [Lightitup Demo](demo/lightitup/README.md)
