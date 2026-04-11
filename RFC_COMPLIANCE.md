# BreathGSLB RFC Compliance Matrix

This document is the tracked RFC audit for the current authoritative DNS
feature set in BreathGSLB.

For the detailed clause-by-clause answer-path audit of the core authoritative
behavior, see [RFC_1035_2181_AUDIT.md](RFC_1035_2181_AUDIT.md).

It is intentionally narrower than "all of DNS". BreathGSLB is an
authoritative-only server with product-specific configuration policy. This
matrix therefore distinguishes between:

- protocol compliance for the implemented authoritative feature set
- stricter product policy chosen by BreathGSLB
- features that are intentionally out of scope today

## Status Meanings

- `Compliant`: implemented for the current feature surface and covered by code
  paths and tests
- `Partial`: implemented in material parts, but not fully audited or not a full
  implementation of the entire RFC feature set
- `Out of scope`: not implemented by design in the current project

## Scope Boundary

This matrix is about the current BreathGSLB runtime:

- authoritative answers only
- forward zones and delegated reverse zones
- DNSSEC signing and signed transfer serving
- TSIG-authenticated AXFR and IXFR
- EDNS(0) handling relevant to authoritative service

This matrix is not a claim that BreathGSLB implements every DNS feature or
every standards-track DNS transport.

## Compliance Matrix

| RFC | Area | Status | Current BreathGSLB Position | Code / Tests |
| --- | --- | --- | --- | --- |
| [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034.html) | Core DNS concepts, authoritative operation | Partial | BreathGSLB behaves as an authoritative-only server and does not recurse. It serves configured zones, enforces AA/authoritative behavior, and uses a stricter product policy to keep forward and reverse zones separate. It is not a generic full-featured RFC 1034 implementation for every DNS feature. | `src/dns_functions.go`, `src/recursion_test.go` (`TestRecursionDisabled`), `src/config/validate.go`, `src/config/validate_test.go` (`TestValidateForwardAndReverseZoneSeparation`) |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) | DNS message format, RR types, SOA/NS/A/PTR/TXT, AXFR base behavior | Partial | Core authoritative RR serving is implemented for the RR types BreathGSLB exposes. AXFR support exists. BreathGSLB intentionally rejects direct `PTR` in forward zones and rejects forward-style policy in reverse zones, even though bare DNS syntax is broader. The project is not yet audited as a complete RFC 1035 server for every RR and every zone-file behavior. | `src/dns_functions.go`, `src/config/validate.go`, `src/reverse_ptr_test.go`, `src/lightup_ptr_test.go`, `src/replication_test.go` (`TestAXFRUnsignedAllowedAndSigned`) |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181.html) | Clarifications to core DNS behavior | Partial | The clause-by-clause answer-path audit now exists, including RRSet truncation and TTL-uniformity checks, but some areas remain partial, especially zone cuts, reply-source testing on multi-homed listeners, and general duplicate-RRSet auditing. | [RFC_1035_2181_AUDIT.md](RFC_1035_2181_AUDIT.md), `src/dnssec_functions.go`, `src/nsec_test.go`, `src/dnssec_nxdomain_test.go`, `src/rfc_1035_2181_test.go`, `src/config/validate_test.go` |
| [RFC 1912](https://www.rfc-editor.org/rfc/rfc1912.html) | Operational DNS guidance | Partial | This is operational guidance rather than a protocol spec. BreathGSLB now enforces a stronger separation between forward and reverse zones and supports forward/reverse symmetry for lightup names, which aligns with the spirit of RFC 1912. It is still guidance, not a binary compliance target. | `src/config/validate.go`, `src/lightup_forward_test.go`, `src/lightup_ptr_test.go` |
| [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596.html) | AAAA and `ip6.arpa` IPv6 reverse DNS | Compliant | AAAA serving and IPv6 reverse under `ip6.arpa.` are first-class features. BreathGSLB supports explicit IPv6 reverse zones, synthetic IPv6 PTRs, and exact forward/reverse template round-tripping for lightup IPv6 names. | `src/dns_functions.go`, `src/lightup_functions.go`, `src/reverse_ptr_test.go`, `src/lightup_ptr_test.go`, `src/lightup_forward_test.go` |
| [RFC 1995](https://www.rfc-editor.org/rfc/rfc1995.html) | IXFR | Partial | IXFR exists and is tested, and the server is allowed to fall back to AXFR when an incremental diff is unavailable. The current implementation is practical rather than exhaustively audited against every IXFR transport and history-retention corner case. | `src/dns_functions.go`, `src/mux_functions.go`, `src/integration_test.go` (`TestIntegrationIXFR`) |
| [RFC 1996](https://www.rfc-editor.org/rfc/rfc1996.html) | DNS NOTIFY | Out of scope | NOTIFY is not implemented. Zone convergence currently relies on polling, discovery reload, AXFR, IXFR, and explicit reload signals rather than RFC 1996 notifications. | No implementation present |
| [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136.html) | DNS UPDATE | Out of scope | Dynamic update is not implemented. BreathGSLB is currently a config-and-transfer driven authoritative server, not an RFC 2136 dynamic update server. | No implementation present |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html) / [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034.html) / [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html) | DNSSEC | Partial | BreathGSLB signs authoritative data, serves `DNSKEY`, `RRSIG`, `NSEC`, and `NSEC3`, supports generated and manual keys, and transfers signed data to secondaries. DNSSEC denial proofs and NSEC/NSEC3 behavior are materially covered. Full DNSSEC ecosystem scope such as resolver validation, parent-side DS publication workflow, CDS/CDNSKEY automation, and every DNSSEC extension RFC are not in scope here. | `src/dnssec_functions.go`, `src/dns_functions.go`, `src/dnssec_generated_test.go`, `src/dnssec_nxdomain_test.go`, `src/nsec_test.go`, `src/nsec3_test.go`, `src/replication_test.go` (`TestAXFRIncludesDNSSECRRs`, `TestSecondaryServesTransferredDNSSECData`) |
| [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html) | EDNS(0) | Partial | BreathGSLB handles EDNS OPT records, DO-bit-driven DNSSEC behavior, configured UDP buffer sizing, and reads ECS data where used for selection. It does not claim support for every EDNS option or every EDNS error path. | `src/dns_functions.go`, `src/config/load.go`, DNSSEC tests that attach OPT/DO records such as `src/dnssec_generated_test.go`, `src/dnssec_nxdomain_test.go`, `src/nsec3_test.go` |
| [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html) | Extended DNS Errors (EDE) | Out of scope | BreathGSLB does not currently emit authoritative EDE values. User-observed `EDE: 22` / `EDE: 23` responses in recursive lookups came from upstream recursive resolvers, not from BreathGSLB itself. | No authoritative EDE generation in repo code |
| [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945.html) | TSIG | Partial | TSIG is implemented for authenticated AXFR/IXFR and discovery bootstrap. Key generation/loading, MAC chaining, ACLs, wrong-key rejection, and mismatched signature rejection are covered. The project is not a full generic TSIG consumer for every DNS message class, but the implemented transfer path is materially compliant. | `src/config/load.go`, `src/dns_functions.go`, `src/authority_functions.go`, `src/discovery_functions.go`, `src/tsig_test.go`, `src/replication_test.go` |
| [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html) | CAA | Partial | BreathGSLB supports static authoritative CAA records in forward zones and validates their config shape. There is no dynamic CAA policy engine; this is static authoritative serving only. | `src/config/validate.go`, forward answer path in `src/dns_functions.go`, config tests in `src/config/validate_test.go` |
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698.html) | TLSA / DANE | Out of scope | BreathGSLB does not currently expose first-class TLSA record configuration or DANE-specific handling. | No implementation present |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html) | DNS over TLS | Out of scope | BreathGSLB currently serves classic DNS over UDP/TCP. It does not implement DoT listener support. | No implementation present |
| [RFC 9103](https://www.rfc-editor.org/rfc/rfc9103.html) | Zone transfer over TLS (XoT) | Out of scope | AXFR and IXFR are currently TCP plus optional TSIG. XoT is not implemented. | No implementation present |

## Product Policy Versus Bare DNS Syntax

The code intentionally enforces stricter product policy than the DNS wire
protocol requires.

Examples:

- RFC 1035 defines `PTR` as a generic RR type, but BreathGSLB forbids direct
  `PTR` in forward zones.
- Reverse zones in BreathGSLB are limited to reverse-mapping intent:
  explicit or synthetic `PTR`, plus zone metadata, DNSSEC, and transfer
  settings.
- Forward-only policy layers such as pools, hosts, ALIAS behavior, geo
  steering, and health checks are rejected in reverse zones.

This policy is implemented to reduce operator error and keep the runtime model
coherent. It is stricter than bare DNS syntax by design.

## Current Gaps Worth Closing

These are the most obvious standards-related gaps still visible after the
current audit:

1. Extend the clause-by-clause audit in
   [RFC_1035_2181_AUDIT.md](RFC_1035_2181_AUDIT.md) into the remaining
   partial areas, especially zone cuts and multi-homed reply-source testing.
2. Decide whether authoritative EDE should be emitted for selected failure
   cases, or remain intentionally absent.
3. Decide whether NOTIFY is needed, or whether polling plus reload plus IXFR is
   sufficient for this project.
4. Decide whether DoT/XoT are future roadmap items or permanently out of scope.
5. Expand the compliance matrix if new first-class RR types are added, such as
   TLSA.

## Current Review Rule

Any new DNS behavior should update:

- this file
- [dnsrfc/README.md](dnsrfc/README.md)
- the operator config docs in [src/doc/configuration.md](src/doc/configuration.md)

That keeps standards references, product policy, and runtime behavior from
drifting apart.
