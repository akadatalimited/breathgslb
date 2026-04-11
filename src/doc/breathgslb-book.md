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
{{breathgslb_manual}}
```

### breathgslb.conf(5)

```markdown
{{breathgslb_conf_manual}}
```
