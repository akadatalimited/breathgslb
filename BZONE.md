# BZONE

## Purpose

`bzone` is the planned primary-side configuration tool for BreathGSLB.

Its job is not to answer DNS. Its job is to validate and write BreathGSLB
config and zone files safely so operators do not have to hand-edit nibble-form
reverse names or large YAML structures for routine changes.

The division of responsibility is:

* `breathgslb` reads and serves config
* `bzone` validates and writes config

`bzone` should run on primary servers.

## Design Goals

`bzone` should:

* read the main BreathGSLB config to find `zones_dir` and `reverse_dir`
* hide manual reverse nibble conversion from the operator
* refuse writes outside the delegated prefix or reverse zone
* preserve the current config model: zones, hosts, pools, lightup, TSIG, DNSSEC
* write normal BreathGSLB YAML, not invent a second storage format
* leave SOA serial handling to BreathGSLB runtime persistence

It should not require operators to hand-build reverse owners such as:

* IPv6 nibble `ip6.arpa` owners
* IPv4 `in-addr.arpa` owners

## Current Scope

The safest first scope is:

* reverse zone creation from a CIDR
* PTR add and delete from a CIDR plus IP
* host add and delete for forward zones

The initial command surface should be:

```sh
bzone zone create forward
bzone zone create reverse --tonibble <cidr>
bzone zone add-ptr --tonibble <cidr> --ip <ip> --ptr <name>
bzone zone delete-ptr --tonibble <cidr> --ip <ip>
bzone zone add-host --zone <fqdn> --name <host>
bzone zone delete-host --zone <fqdn> --name <host>
```

Later work can add:

* `add-pool`
* `edit-pool`
* `delete-pool`
* `add-geo`
* `edit-geo`
* `delete-geo`

## Why `--tonibble`

For reverse work, `--tonibble` is the right operator-facing input.

Operators normally know:

* the delegated prefix
* the IP they want to map

They should not have to hand-convert either value into reverse DNS nibble
notation.

Examples:

```sh
bzone zone create reverse \
  --tonibble 2a02:8012:bc57:5353::/64 \
  --ns gslb.zerodns.co.uk. \
  --ns gslb2.zerodns.co.uk. \
  --admin hostmaster.zerodns.co.uk.
```

```sh
bzone zone add-ptr \
  --tonibble 2a02:8012:bc57:5353::/64 \
  --ip 2a02:8012:bc57:5353::1 \
  --ptr gslb.zerodns.co.uk. \
  --ttl 300
```

IPv4 should work the same way:

```sh
bzone zone create reverse --tonibble 172.16.0.0/24 ...
bzone zone add-ptr --tonibble 172.16.0.0/24 --ip 172.16.0.42 --ptr app.example. --ttl 300
```

## Reverse Zone Create

`bzone zone create reverse --tonibble <cidr>` should:

1. validate the supplied CIDR
2. derive the correct reverse zone name
3. create a BreathGSLB reverse zone file in `reverse_dir`
4. write:
   * `name`
   * `ns`
   * `admin`
   * SOA timers and TTLs
   * an initial `serve` mode, normally `primary`
5. refuse to overwrite existing zone data unless explicitly asked

Expected output is a normal `*.rev.yaml` file.

## PTR Add And Delete

`bzone zone add-ptr --tonibble <cidr> --ip <ip> --ptr <name>` should:

1. validate the CIDR
2. validate the IP
3. confirm the IP is inside the delegated prefix
4. derive the reverse zone name from the CIDR
5. derive the correct owner name inside that reverse zone
6. write or update the `ptr:` section in the correct `*.rev.yaml`

`delete-ptr` should perform the same validation and then remove the matching
owner entry.

The tool must refuse:

* IPs outside the delegated prefix
* malformed IPs
* PTR targets that are not valid DNS names
* writes to the wrong reverse zone

## Forward Host Add And Delete

`bzone zone add-host` and `delete-host` are the first forward-zone mutation
commands because they align with the current host-and-pool runtime model.

Example intent:

```sh
bzone zone add-host --zone lightitup.zerodns.co.uk. --name app
bzone zone delete-host --zone lightitup.zerodns.co.uk. --name app
```

The initial host commands should:

* find the correct forward zone file in `zones_dir`
* validate that the host is inside the zone
* create or remove a `hosts:` entry
* avoid inventing implicit pool data unless explicitly requested later

That keeps the first write path safe and narrow.

## Config Discovery

The common path should not require `--file`.

`bzone` should:

1. read the main BreathGSLB config
2. discover `zones_dir` and `reverse_dir`
3. locate the target zone file automatically

`--file` can still exist as an override for unusual cases, but it should not be
required for routine operations.

## Serials

Operators should not have to manage SOA serials manually.

BreathGSLB already maintains serial state in:

* `/etc/breathgslb/serials/`

with automatic time-based progression.

`bzone` should therefore:

* write config and zone content
* not require the operator to set a serial by hand
* rely on BreathGSLB reload/runtime behavior to advance serials safely

## Validation Rules

`bzone` should validate before it writes:

* zone exists or can be created
* name is within the zone
* IP family matches the operation
* `--ip` belongs to `--tonibble`
* reverse owner maps to the correct zone
* no malformed YAML is produced

This is the main operational reason for the tool: prevent easy human error in
authoritative zone editing.

## Relation To Other Documents

This tool is part of the current config and replication model, not a separate
system.

Related documents:

* [POOLS](./POOLS.md)
* [ZONE_REPLICATION](./ZONE_REPLICATION.md)
* [LIGHTITUP](./LIGHTITUP.md)
* [LIGHTITUP_PHASE1](./LIGHTITUP_PHASE1.md)

If the command surface changes, this file should be updated before
implementation drifts.
