# Lightitup Demo

This demo mirrors the live `lightitup` development setup and now includes two
authoritative node profiles:

- `gslb.zerodns.co.uk.` -> `2a02:8012:bc57:53::1`
- `gslb2.zerodns.co.uk.` -> `2a02:8012:bc57:53a::1`
- light-up test space -> `2a02:8012:bc57:5353::/64`
- private test space -> `172.16.0.0/24`

It installs directly into `/etc/breathgslb` via `sudo make demodata`.

## What it contains

- primary config: `/etc/breathgslb/config.yaml`
- secondary config: `/etc/breathgslb/config.gslb2.yaml`
- primary zone data under `/etc/breathgslb/zones` and `/etc/breathgslb/reverse`
- explicit secondary zone data under `/etc/breathgslb/zones-secondary` and
  `/etc/breathgslb/reverse-secondary`
- generated DNSSEC key material under `/etc/breathgslb/keys`
- transfer key material under `/etc/breathgslb/tsig`
- serial snapshots under `/etc/breathgslb/serials`

The primary remains explicit and deterministic. The secondary is a true
`serve: "secondary"` replica with `masters:` pointing at
`[2a02:8012:bc57:53::1]:53` and `xfr_source: "2a02:8012:bc57:53a::1"` so AXFR
comes from the nameserver address rather than whatever source the kernel picks.
There is no promotion or election logic in this demo step.

Both the forward and delegated reverse zones use `dnssec.mode: generated` with
stable key paths under `/etc/breathgslb/keys/` and default to plain NSEC with
`nsec3_iterations: 0`. The secondary keeps matching DNSSEC and `lightup`
configuration locally while AXFR remains the source of zone content.

The demo forward zone now uses the new apex `pools:` model directly. It keeps
the older apex `a_master` / `aaaa_master` style fields alongside it only as a
transition bridge for the current replication path. The primary answer path is
expected to select from named pools first.

The demo also includes a first-class in-zone host:

- `app.lightitup.zerodns.co.uk.` with its own public and private pools for `A`
  and `AAAA`
- `app.lightitup.zerodns.co.uk.` also carries an explicit host-level
  `health:` block, proving zone-default then host-override inheritance

The demo also enables the current geo steering model:

- `GB`, `FR`, `DE`, and the wider `EU` region prefer the `public-v*-primary`
  pools
- `US`, `CA`, and the wider `NA` region prefer the `public-v*-secondary`
  pools
- everyone else falls back to the fallback pool

Geo lookups use `/etc/breathgslb/geoip/GeoLite2-Country.mmdb`. Install a local
MaxMind country database there if you want live geo behaviour instead of the
non-geo fallback path.

## Reverse Zones

For `2a02:8012:bc57:5353::/64` the delegated reverse zone is:

`3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.`

For `172.16.0.0/24` the delegated reverse zone is:

`0.16.172.in-addr.arpa.`

Use the full nibble-form owner for IPv6 PTR lookups. A shortened owner such as
`1.1.1.3.5.3.5...ip6.arpa.` correctly returns `NXDOMAIN`.

The private IPv4 family reserves:

- `172.16.0.1` for `route.lightitup.zerodns.co.uk.`
- `172.16.0.2` for `homer.lightitup.zerodns.co.uk.`

All other `172.16.0.0/24` addresses synthesize through the configured lightup
template.

## Suggested Checks

```sh
sudo make demodata
breathgslb -config /etc/breathgslb/config.yaml
breathgslb -config /etc/breathgslb/config.gslb2.yaml
source aliases
alltest
restest 2a02:8012:bc57:5353::abc1:abc1
CHECK_IPV4=1 alltest

dig @2a02:8012:bc57:53::1 NS lightitup.zerodns.co.uk.
dig @2a02:8012:bc57:53a::1 NS lightitup.zerodns.co.uk.
dig @2a02:8012:bc57:53::1 AAAA app.lightitup.zerodns.co.uk.
dig @2a02:8012:bc57:53::1 A app.lightitup.zerodns.co.uk.
dig @2a02:8012:bc57:53::1 PTR 1.1.1.3.0.0.0.0.0.0.0.0.0.0.0.0.3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.
dig @2a02:8012:bc57:53::1 PTR 42.0.16.172.in-addr.arpa.
dig @2a02:8012:bc57:53::1 A templated-172-16-0-42.lightitup.zerodns.co.uk.
dig +dnssec @2a02:8012:bc57:53a::1 DNSKEY lightitup.zerodns.co.uk.
```

`alltest` runs the tracked `scripts/lightitup-smoketest` pass/fail suite
against both authoritative servers. `restest` is the focused reverse/forward
round-trip check for a single IP. By default the smoke test is IPv6-first and
skips direct `A` answer enforcement; set `CHECK_IPV4=1` to require apex and
host `A` parity too.

The current geo model is still anchored around the apex pools. Host-level
`A`/`AAAA` records now exist through `hosts:` with per-host pools, and the demo
includes one explicit host-level `health:` override. Richer host-level geo
policy remains future work.

Sync the replica state that AXFR does not carry with:

```sh
scripts/slavesync /etc/breathgslb /srv/breathgslb-gslb2
scripts/slavesync --check /etc/breathgslb /srv/breathgslb-gslb2
```

`slavesync` copies `keys/`, `tsig/`, and `serials/`. AXFR and IXFR remain the
authoritative source of RR content.

## Parent Zone Note

The NS host AAAA records for `gslb.zerodns.co.uk.` and
`gslb2.zerodns.co.uk.` live in the parent `zerodns.co.uk.` zone, not inside
this child demo zone. The child forward and reverse zones should delegate to
both nameserver hostnames once glue is published.

## Keeping Demo Data In Sync

Use:

```sh
make sync-demodata
```

That syncs the live primary `/etc/breathgslb` tree back into `demo/lightitup/`
and keeps the repo copy normalized to the file-based layout.
