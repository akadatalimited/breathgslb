# BreathGSLB Pools And Hosts Model

## Purpose

This document defines the next internal service model for BreathGSLB.

It is the authoritative design for moving from the current apex-centric
`master` / `standby` / `fallback` fields to a reusable `hosts` + `pools`
model that supports:

* apex and non-apex `A` / `AAAA` answers inside the same zone
* multiple addresses per host and per family
* private and public answer classes
* geo and local-policy selection
* health-driven filtering
* replication and DNSSEC without a second answer engine

Configured truth still comes first. Health and policy only choose between
configured candidates.

## Core Decision

BreathGSLB should use one internal runtime model:

* a zone contains one or more hosts
* a host contains one or more pools
* a pool contains one or more answer members

Legacy apex fields remain accepted only as compatibility input until they are
removed later. They should be translated into pools during config loading.

Do not expand the legacy `master` / `standby` / `fallback` field set further.

## Host Model

The zone apex becomes a normal host with `name: "@"`.

Non-apex names are also hosts and must be able to define first-class `A` and
`AAAA` answers within the zone, not only `alias_host` or lightup synthesis.

Example:

```yaml
zones:
  - name: "lightitup.zerodns.co.uk."
    ns: ["gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."]
    admin: "hostmaster.zerodns.co.uk."

    hosts:
      - name: "@"
        pools:
          - name: "public-v6-eu"
            family: "ipv6"
            class: "public"
            role: "primary"
            members:
              - ip: "2a02:8012:bc57:5353::10"
              - ip: "2a02:8012:bc57:5353::20"

      - name: "example"
        pools:
          - name: "public-v4-us"
            family: "ipv4"
            class: "public"
            role: "secondary"
            members:
              - ip: "13.41.102.90"
```

## Current Non-Apex Host Policy Review

The current non-apex host model is the correct direction, but it needs strict
policy boundaries so the config does not drift into multiple competing naming
systems.

Current policy:

* non-apex hosts are explicit configured names, not free-form label parsing
* first-class in-zone `A` and `AAAA` for non-apex names come from `hosts[].pools`
* host `alias` and zone `alias_host` remain ALIAS-style behavior, not first-class `CNAME`
* `hosts[].alias` and `hosts[].pools` are mutually exclusive
* `lightup` remains deterministic synthesis below configured host truth
* zone health is the default, host health is the first real override
* named-pool `geo` is preferred over legacy role-based geo for new config
* named-pool `geo` and legacy `master` / `standby` / `fallback` geo must not be mixed in the same block
* secondaries must persist and reload the full host policy model, not a flattened serving cache

What this means operationally:

* use `hosts:` when you want a real hostname inside the zone to have steerable `A` or `AAAA`
* use `hosts[].alias` or `alias_host` when you want ALIAS-style target resolution
* use `lightup` when the name should be generated from owned address space
* do not expect arbitrary labels such as `trash.example.` to synthesize unless `lightup` explicitly allows that template

Current intentional limits:

* no wildcard host policy engine
* no first-class `cname:` section
* no pool-level or member-level health overrides by default
* no second answer engine for non-apex names; hosts and apex must keep using the same pool logic

This is the stable policy baseline for future host work.

## Pool Model

A pool is a candidate answer group. It must carry actual answer members.

Recommended fields:

* `name`: stable pool identifier
* `family`: `ipv4` or `ipv6`
* `class`: `public`, `private`, or later other explicit classes
* `role`: `primary`, `secondary`, `fallback`, `internal`, or another explicit policy label
* `members`: list of `ip` entries returned in DNS answers
* `client_nets`: optional CIDRs that make the pool eligible for the source client
* `weight`: optional later work
* `priority`: optional later work
* `health`: optional host override later

Important: `client_nets` are not answer data. They are policy matchers.

## Selection Model

The runtime answer engine should do this:

1. match the queried owner name to one host
2. choose pools matching query family and client locality
3. apply geo policy
4. filter unhealthy members
5. return one or more surviving records
6. pass through the existing DNSSEC and negative-answer path

This must be the same engine for apex and non-apex hosts.

## Geo Model

Current geo logic should be reused, not replaced with a second system.

Near-term rule:

* `geo` remains a policy block that prefers roles such as `primary`,
  `secondary`, and `fallback`
* `geo_answers` remains an explicit override layer

Longer term:

* geo may select pool names directly, but that is not required for the first
  pool implementation

## Local And Private Policy

Private/public selection should become pool eligibility, not hardcoded apex
special cases.

Use:

* `class` to distinguish public vs private answers
* `client_nets` to declare which source networks are eligible for a pool

That replaces the current split between:

* `a_master_private` / `aaaa_master_private`
* `rfc_master` / `ula_master`

while still allowing a compatibility adapter for old configs.

## Health Model

Health remains a filter over configured members.

The first implementation may keep health at host level to avoid a wide rewrite.
Later work may allow pool-specific or member-specific health overrides.

Do not create separate health engines for apex and non-apex hosts.

## Lightup Interaction

Lightup remains below configured host truth.

Order must stay:

1. exact configured host records
2. health and policy selection from configured pools
3. lightup synthesis
4. NODATA or NXDOMAIN

Lightup must never override a configured host or a configured pool member.

## Replication And DNSSEC

Pools and hosts are config and authoritative state. They must replicate through
the same primary/secondary model already in use.

Rules:

* AXFR and IXFR remain the source of RR content
* TSIG continues to protect transfers
* DNSSEC signing stays in the common answer path
* secondaries must answer identically for configured host records and lightup
* private keys and TSIG secrets still require separate synchronization where
  AXFR does not carry them

See [ZONE_REPLICATION.md](./ZONE_REPLICATION.md) for replication notes.

## Compatibility Plan

The migration must be loader-driven, not a flag day rewrite.

Phase 1:

* add internal `HostService` and `Pool` runtime structs
* translate legacy apex config into one implicit host `@` with pools
* preserve current behavior exactly

Phase 2:

* add explicit `hosts:` config
* allow host-level `A` / `AAAA` answers through pools
* keep apex legacy fields supported

Phase 3:

* move local/private and geo selection onto pools
* keep `lightup` below configured host answers

Phase 4:

* deprecate direct `a_master` / `aaaa_master` style config
* remove legacy fields only after compatibility tests are complete

## Immediate Action Plan

1. Define internal host and pool structs.
2. Add loader translation from legacy apex fields to pools.
3. Add tests proving existing configs behave unchanged.
4. Add explicit `hosts:` syntax with `name: "@"` for apex.
5. Add non-apex host `A` / `AAAA` support through the same pool engine.
6. Extend geo and local-policy tests to cover host-level pools.
7. Update replication tests so primary and secondary serve identical host answers.

## Document Status

This file is the current architecture plan for host and pool evolution.

Related documents:

* [LIGHTITUP.md](./LIGHTITUP.md)
* [LIGHTITUP_PHASE1.md](./LIGHTITUP_PHASE1.md)
* [ZONE_REPLICATION.md](./ZONE_REPLICATION.md)

If those documents conflict with this host/pool model, this document should be
treated as the current design authority for future work.
