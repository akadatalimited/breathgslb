# DNS RFC Notes

This directory is a local reminder set for RFCs that matter to BreathGSLB
behavior and configuration policy.

It is not a mirror of the full RFC texts. It is a curated index of the RFCs
that most directly affect how this repository should behave.

The tracked implementation status for the current authoritative feature set is
in:

- [RFC Compliance Matrix](../RFC_COMPLIANCE.md)

## Core DNS

- RFC 1034: Domain Concepts and Facilities
  https://www.rfc-editor.org/rfc/rfc1034.html
- RFC 1035: Domain Implementation and Specification
  https://www.rfc-editor.org/rfc/rfc1035.html
- RFC 2181: Clarifications to the DNS Specification
  https://www.rfc-editor.org/rfc/rfc2181.html

Repo notes:

- RFC 1035 defines `PTR` as a general pointer RR type and `TXT` as descriptive
  text whose semantics depend on the domain where it appears.
- That means `PTR` and `TXT` are syntactically valid DNS data types in the
  protocol.
- BreathGSLB still chooses a stricter product policy: forward zones are for
  forward records, and delegated reverse zones are treated as reverse-mapping
  zones.

## Reverse DNS

- RFC 1035: `IN-ADDR.ARPA` reverse mapping for IPv4
  https://www.rfc-editor.org/rfc/rfc1035.html
- RFC 3596: DNS Extensions to Support IP Version 6
  https://www.rfc-editor.org/rfc/rfc3596.html
- RFC 1912: Common DNS Operational and Configuration Errors
  https://www.rfc-editor.org/rfc/rfc1912.html

Repo notes:

- `in-addr.arpa.` and `ip6.arpa.` are the normal reverse trees.
- Reverse-mapping practice is operationally centered on `PTR`, `NS`, `SOA`, and
  DNSSEC/transfer metadata.
- RFC 1912 is operational guidance, not the base protocol, but it is useful for
  pointer hygiene and forward/reverse consistency.

## DNSSEC

- RFC 4033: DNS Security Introduction and Requirements
  https://www.rfc-editor.org/rfc/rfc4033.html
- RFC 4034: DNSSEC Resource Records
  https://www.rfc-editor.org/rfc/rfc4034.html
- RFC 4035: DNSSEC Protocol Modifications
  https://www.rfc-editor.org/rfc/rfc4035.html

Repo notes:

- BreathGSLB uses DNSSEC in the common answer path.
- NSEC/NSEC3 denial must match what the server actually serves.

## EDNS and Errors

- RFC 6891: EDNS(0)
  https://www.rfc-editor.org/rfc/rfc6891.html
- RFC 8914: Extended DNS Errors
  https://www.rfc-editor.org/rfc/rfc8914.html

Repo notes:

- EDNS size handling and EDE output should remain standards-aligned.

## Transfer Authentication and Transport

- RFC 8945: Secret Key Transaction Authentication for DNS (TSIG)
  https://www.rfc-editor.org/rfc/rfc8945.html
- RFC 7858: DNS over TLS
  https://www.rfc-editor.org/rfc/rfc7858.html
- RFC 9103: DNS Zone Transfer over TLS
  https://www.rfc-editor.org/rfc/rfc9103.html

Repo notes:

- Current replication work is TSIG-centered.
- Zone transfer transport should remain compatible with these standards as the
  implementation evolves.

## Other Record Extensions

- RFC 8659: CAA
  https://www.rfc-editor.org/rfc/rfc8659.html
- RFC 6698: TLSA / DANE
  https://www.rfc-editor.org/rfc/rfc6698.html

## Current BreathGSLB Policy Derived From The RFCs

BreathGSLB currently enforces the following product policy:

- forward zones must not define direct `PTR` records
- reverse zones must not define forward host pools, ALIAS, geo steering, or health checks
- reverse zones are for explicit/generated/synthetic `PTR` plus zone/DNSSEC/transfer metadata

This is stricter than bare DNS syntax, but it matches normal authoritative DNS
operation and reduces operator error.
