# Lightitup Demo

This demo mirrors the current live `lightitup` development setup:

- base network -> `2a02:8012:bc57::/48`
- `gslb.zerodns.co.uk.` listener -> `2a02:8012:bc57:53::1`
- light-up test space -> `2a02:8012:bc57:5353::/64`

It installs directly into `/etc/breathgslb`
via `sudo make demodata`.

## What it contains

- `lightitup.zerodns.co.uk.` forward zone
- `3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.` delegated reverse zone for
  `2a02:8012:bc57:5353::/64`, installed under `/etc/breathgslb/reverse`
- generated DNSSEC key material written under `/etc/breathgslb/keys`
- the current `lightitup` template values for `serve`, health checks, and
  master/standby addresses
- a `lightup` config block using
  `2a02:8012:bc57:5353::/64`
- explicit listeners on `2a02:8012:bc57:53::1:53` and
  `2a02:8012:bc57:5353::1:53`

The demo still does not enable forward light-up synthesis. It uses the live
forward template plus explicit PTR records so reverse delegation is testable
without changing existing forward behaviour.

Both the forward and delegated reverse demo zones use `dnssec.mode: generated`
with stable key paths under `/etc/breathgslb/keys/`. The demo defaults to plain
NSEC with `nsec3_iterations: 0`; NSEC3 can be enabled later once the NSEC path
is verified cleanly.

## Important reverse correction

For `2a02:8012:bc57:5353::/64` the delegated reverse zone is:

`3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.`

That matches the `/64` nibble cut exactly. The demo is now aligned to that
delegation shape.

## Suggested checks

```sh
sudo make demodata
breathgslb -config /etc/breathgslb/config.yaml

dig @2a02:8012:bc57:53::1 AAAA lightitup.zerodns.co.uk.
dig @2a02:8012:bc57:53::1 PTR 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.
dig @2a02:8012:bc57:53::1 PTR 3.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.
dig @2a02:8012:bc57:53::1 PTR 1.1.1.3.0.0.0.0.0.0.0.0.0.0.0.0.3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.
```

Use the full nibble-form owner for IPv6 PTR lookups. A shortened name such as
`1.1.1.3.5.3.5...ip6.arpa.` will correctly return `NXDOMAIN`.

## Keeping Demo Data In Sync

Use:

```sh
make sync-demodata
```

That pulls the live `/etc/breathgslb` demo install back into
`demo/lightitup/`. It copies the live `zones/` and `reverse/` files and
normalizes `config.yaml` back to the file-based demo layout so ad hoc inline
`zones:` edits in `/etc/breathgslb/config.yaml` do not get committed back into
the repo by mistake.
