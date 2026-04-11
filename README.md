# BreathGSLB

BreathGSLB is an authoritative DNS server with health-aware answer selection,
GeoIP routing, DNSSEC signing, deterministic lightup synthesis, and
primary/secondary replication.

The current runtime model is:

- one main config for listeners, timing, GeoIP, TSIG, and discovery
- forward zones loaded from `zones_dir` as `*.fwd.yaml`
- reverse zones loaded from `reverse_dir` as `*.rev.yaml`
- primary or discovery-based secondary operation
- apex and named hosts answered through the same pool model

BreathGSLB is authoritative only. It does not recurse.

## What It Does

- health-steered `AAAA` and `A` answers
- apex pools and in-zone host pools
- named-pool geo routing by country and continent
- local/private answers using client CIDR matching
- lightup forward and reverse synthesis for IPv6 and IPv4
- live delegated reverse zone serving
- DNSSEC with generated or manual keys
- TSIG-protected AXFR/IXFR
- catalog-based secondary discovery
- persisted secondary snapshots for restart durability

## Documentation

The current config source of truth is:

- [Configuration](src/doc/configuration.md)

Current examples are here:

- [Primary Example](src/doc/examples/config.yaml)
- [Sample Config](src/doc/examples/config.sample.yaml)
- [Minimal Geo Example](src/doc/examples/minimal-geo.yaml)

Live demo material is here:

- [Lightitup Demo](demo/lightitup/README.md)

Design documents for the current direction:

- [POOLS](POOLS.md)
- [Zone Replication](ZONE_REPLICATION.md)
- [Lightup Plan](LIGHTITUP.md)
- [Lightup Phase 1 Notes](LIGHTITUP_PHASE1.md)

Service and API references:

- [Services](src/doc/services.md)
- [API](src/doc/api.md)

## Build

From the repository root:

```sh
make build
```

The binary is written to:

```sh
./breathgslb
```

Install it if you want it on `PATH`:

```sh
sudo install -m 0755 ./breathgslb /usr/local/bin/breathgslb
```

## Run

Typical primary start:

```sh
./breathgslb -config /etc/breathgslb/config.yaml
```

Typical discovery-based secondary start:

```sh
./breathgslb -config /etc/breathgslb/config.gslb2.yaml
```

## Config Layout

BreathGSLB now expects:

- main config for global settings and optional inline zones
- `/etc/breathgslb/zones/*.fwd.yaml` for forward zones
- `/etc/breathgslb/reverse/*.rev.yaml` for reverse zones
- `/etc/breathgslb/keys/` for DNSSEC keys
- `/etc/breathgslb/tsig/` for TSIG keys
- `/etc/breathgslb/serials/` for SOA serial state

For a discovery secondary, the main config is enough to bootstrap. The
secondary discovers zones from the primary catalog, transfers them, and writes
local secondary snapshots for restart safety.

## Answer Model

Resolution order is:

1. exact host match in `hosts:`
2. host `alias` or zone `alias_host`
3. `lightup` synthesis for matching names
4. apex pools or legacy apex fields
5. static records such as `TXT`, `MX`, `CAA`, `RP`, `SSHFP`, `SRV`, `NAPTR`,
   `PTR`

Important distinctions:

- `hosts:` gives first-class in-zone names such as `app.example.net.`
- `pools:` are the current answer-selection model for apex and named hosts
- legacy `a_master` / `aaaa_master` style fields still work, but pools are the
  forward direction

## Geo Routing

Geo routing uses a MaxMind country MMDB and exact ISO code matching.

The code reads:

- `country.iso_code`
- `registered_country.iso_code`
- `continent.code`

Then it compares those values to:

- `allow_countries`
- `allow_continents`

Named-pool geo is the current preferred model. Legacy `geo.master`,
`geo.standby`, and `geo.fallback` are compatibility only.

## Lightup

`lightup` provides deterministic synthetic names and reverse PTRs inside owned
prefixes.

It supports:

- IPv6 public or private families
- IPv4 private families
- exact template round-tripping between PTR and forward names
- exclusion ranges
- explicit-record precedence over synthesis

With an explicit `forward_template`, only names that match that template
synthesize. Arbitrary names under the zone do not synthesize.

## Reverse Zones

Delegated reverse zones are normal first-class zone files in `reverse_dir`.

BreathGSLB can:

- serve explicit reverse zones directly
- generate reverse data from configured records
- synthesize PTRs for lightup ranges

Reverse zone files use `*.rev.yaml`.

## DNSSEC

DNSSEC supports:

- generated keys
- manual key files
- NSEC
- NSEC3
- signed primary answers
- signed secondary answers via transferred signed data

Generated key mode persists keys on disk so restart behavior is stable.

## ALIAS, CNAME, and Named Records

There is no first-class `cname:` section in the current zone schema.

What exists now:

- zone apex `alias`
- named host `alias`
- `alias_host` map for hostname-to-target ALIAS behavior
- first-class host `A` and `AAAA` via `hosts:` and `pools:`
- static named records for `TXT`, `MX`, `CAA`, `RP`, `SSHFP`, `SRV`, `NAPTR`,
  `PTR`

Use:

- `hosts:` when you need real in-zone `A`/`AAAA`
- `alias` or `alias_host` when you need ALIAS-style target resolution
- `lightup` when you need deterministic synthetic names tied to owned prefixes

## Replication

Primary/secondary behavior now supports:

- TSIG-protected AXFR
- `xfr_source`
- IPv4 and IPv6 `allow_xfr_from` CIDRs
- discovery catalog bootstrap
- full policy preservation for secondary snapshots

Secondary snapshots are node-local runtime state. Do not copy another node’s
`serve: secondary` snapshots onto a different server.

## Demo

The live demo under `demo/lightitup` exercises:

- primary and secondary replication
- DNSSEC
- lightup forward/reverse symmetry
- named hosts with pools
- host health override
- public and private address families

Install it with:

```sh
sudo make demodata
```

## Development

Main commands:

```sh
make build
make test
make fmt
make vet
```

Targeted test runs:

```sh
go -C src test -run TestName ./...
```

The repo-local configuration guide is the authoritative reference for config
behavior:

- [Configuration](src/doc/configuration.md)
