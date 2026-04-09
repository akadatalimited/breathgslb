# Lightitup Demo

This demo mirrors the live `lightitup` development setup and now includes two
authoritative node profiles:

- `gslb.zerodns.co.uk.` -> `2a02:8012:bc57:53::1`
- `gslb2.zerodns.co.uk.` -> `2a02:8012:bc57:53a::1`
- light-up test space -> `2a02:8012:bc57:5353::/64`

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
`[2a02:8012:bc57:53::1]:53`. There is no promotion or election logic in this
demo step.

Both the forward and delegated reverse zones use `dnssec.mode: generated` with
stable key paths under `/etc/breathgslb/keys/` and default to plain NSEC with
`nsec3_iterations: 0`. The secondary keeps matching DNSSEC and `lightup`
configuration locally while AXFR remains the source of zone content.

## Reverse Zone

For `2a02:8012:bc57:5353::/64` the delegated reverse zone is:

`3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.`

Use the full nibble-form owner for IPv6 PTR lookups. A shortened owner such as
`1.1.1.3.5.3.5...ip6.arpa.` correctly returns `NXDOMAIN`.

## Suggested Checks

```sh
sudo make demodata
breathgslb -config /etc/breathgslb/config.yaml
breathgslb -config /etc/breathgslb/config.gslb2.yaml

dig @2a02:8012:bc57:53::1 NS lightitup.zerodns.co.uk.
dig @2a02:8012:bc57:53a::1 NS lightitup.zerodns.co.uk.
dig @2a02:8012:bc57:53::1 PTR 1.1.1.3.0.0.0.0.0.0.0.0.0.0.0.0.3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.
dig +dnssec @2a02:8012:bc57:53a::1 DNSKEY lightitup.zerodns.co.uk.
```

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
