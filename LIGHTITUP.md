# BreathGSLB Light-Up DNS Implementation Plan for Codex

## Purpose

Add a light-up DNS layer to BreathGSLB so it can synthesize forward and reverse IPv6 answers for chosen prefixes while preserving the current strengths of the platform:

* authoritative DNS serving
* health-driven apex and record answers
* replication and shared state
* DNSSEC with NSEC and NSEC3
* geo and local-policy awareness
* internal versus external policy decisions
* cross-platform support
* API and future web UI integration

The guiding principle is simple:

Configured truth comes first. Health-driven truth comes second. Light-up synthesis fills the dark space without overriding real data.

---

## Current BreathGSLB Strengths to Preserve

Codex should treat the following as existing strengths that must not be broken:

* shared state
* shared config
* auto promotion / active master behaviour
* DNSSEC built in
* automatic key generation
* NSEC and NSEC3 support
* geo database support for IPv4 and IPv6
* RFC1918 and ULA awareness
* internal versus external answer shaping
* replication support
* TSIG support
* API support
* partial SQLite support
* Linux, Windows, macOS, and BSD support in principle

Mac and BSD support should be treated as needing validation, however not as an afterthought.

---

## Existing Health Check Types

The current health model already supports the following forms and must remain intact:

### HTTP

```yaml
health:
  kind: http
  host_header: "articles.akadata.ltd"
  path: "/health"
  scheme: https
  method: GET
  port: 443
  expect: "OK"
  insecure_tls: false
```

### HTTP/3

```yaml
health:
  kind: http3
  expect: "OK"
```

### TCP with TLS / ALPN

```yaml
health:
  kind: tcp
  port: 443
  tls_enable: true
  sni: "articles.akadata.ltd"
  alpn: "h2"
```

### UDP

```yaml
health:
  kind: udp
  port: 53
  udp_payload_b64: "cGluZw=="
  udp_expect_re: "."
```

### ICMP

```yaml
health:
  kind: icmp
  icmp_payload_b64: "Z3NsYg=="
```

### Raw IP

```yaml
health:
  kind: rawip
  protocol: 47
```

These health checks are not to be redesigned during the first light-up implementation phases.

---

## Existing Replication Model to Preserve

BreathGSLB already has a clear replication model with primary and secondary roles. The following behaviours must remain correct:

* `serve: "primary"` and `serve: "secondary"`
* `masters:` lists for secondary pull
* TSIG-protected transfers
* shared serial handling
* shared authoritative state
* secondaries able to take over cleanly

Light-up configuration and behaviour must replicate correctly. No local-only logic should be introduced.

---

## Existing Full Configuration Example to Keep in Mind

The platform already supports rich configuration such as:

* explicit `listen_addrs`
* interface-derived binding
* API listener and token / cert / key paths
* DNS64 prefix
* EDNS buffer sizing
* logging to syslog
* TSIG path
* zone-level master and standby addresses
* private RFC1918 and private IPv6 / ULA answers
* DNSSEC enablement with KSK and ZSK
* TSIG keys with `allow_xfr_from`
* TXT, MX, CAA, RP and more

Codex should assume the light-up feature must fit naturally into this level of configuration, not simplify the product down into a toy.

---

## Historical Reference: honeyDNS / networklightdns

There is a small historical program which already proves the principle:

* deterministic name to IPv6 synthesis
* authoritative serving for one zone
* fixed NS and glue
* SOA and serial handling
* generated AAAA answers inside a chosen prefix

That code is not the target system. It is the seed of the feature.

BreathGSLB should absorb the principle, not copy the toy whole.

The useful principles from the old code are:

* deterministic name → address mapping
* authoritative answer path
* NODATA / SOA discipline
* stable output for repeated names

What BreathGSLB must add beyond it:

* exclusions for real routed space
* reverse PTR synthesis
* DNSSEC signing for synthesized answers
* replication awareness
* shared state
* internal / external answer shaping
* future health-driven state naming

---

## Core Processing Order

This order is critical and must be preserved:

1. exact configured record
2. health-driven authoritative answer
3. light-up synthesized answer
4. NODATA or NXDOMAIN with SOA

Light-up must never override configured truth.

RFC DNS resolution, defined primarily in
RFC 1034 and RFC 1035, is the standard process for translating human-readable domain names into IP addresses. It uses a distributed, hierarchical system involving stub resolvers, recursive resolvers, root servers, and authoritative servers, often enhanced with security (DNSSEC) and performance features (caching, EDNS0). 
Key RFCs Governing DNS Resolution

    RFC 1034 & 1035 (Core Standards): Defines the fundamental Domain Name System (DNS) concepts, domain structures, and the implementation of resolvers and name servers.
    RFC 2181 (Clarifications): Provides clarifications to the original DNS specifications.
    RFC 2308 (Negative Caching): Defines how to cache "name does not exist" (
    ) responses to improve performance.
    RFC 4697 (Resolution Misbehavior): Documents observed issues in DNS resolution and outlines best practices for iterative resolvers.
    RFC 6147 (DNS64): Describes a mechanism for synthesizing AAAA records from A records to facilitate IPv6 transition. 

The Resolution Process

    Request: A user application sends a query to a local resolver (defined by /etc/resolv.conf).
    Caching: The resolver checks its cache; if the entry is missing or expired, it begins iterative queries.
    Root/TLD/Authoritative: The resolver queries a root server, which refers it to a Top-Level Domain (TLD) server (e.g., .com), which then directs it to the authoritative name server for the specific domain.
    Response: The authoritative server provides the final IP address (A/AAAA record). 

Key Technical Aspects

    Iterative vs. Recursive: While recursive servers do the heavy lifting, authoritative servers provide iterative answers (referrals).
    Caching: To reduce latency, results are stored locally, with TTL (Time-To-Live) managed by negative caching (RFC 2308).
    Security: DNSSEC (RFC 4035) uses cryptographic signatures to ensure record integrity, while EDNS0 (RFC 2671) allows larger UDP packets. 

---

## Phase 1 — Map the Current Answer Path

### Task

Codex should first map the current request flow for:

* forward A answers
* forward AAAA answers
* reverse PTR answers
* DNSSEC signing path
* geo and local-policy path
* replication path
* config loading path

### Files likely involved

* `src/dns_functions.go`
* `src/authority_functions.go`
* `src/zone_index.go`
* `src/dnssec_functions.go`
* `src/geo_functions.go`
* `src/config/*`
* `src/types.go`
* `src/util_functions.go`

### Expected output

Produce a short design note that identifies:

* the exact hook point where synthesized answers should be inserted
* the exact place where DNSSEC signing already happens
* the exact place where reverse lookups are currently handled
* any policy or replication paths that must not be bypassed

No feature work yet. Just map and report.

---

## Phase 2 — Add a `lightup` Zone Configuration Block

### Task

Add a new `lightup` section at zone level.
Light-up must support both public IPv6 and ULA IPv6 prefixes. Synthesized answers must pass through the same local-policy path already used by BreathGSLB so internal clients can receive ULA or RFC1918-aware answers where appropriate. Synthesized answers must also use the normal authoritative response path so EDNS0 buffer handling, truncation, TCP fallback, DNSSEC, NSEC and NSEC3 all continue to behave correctly.

### First proposed shape

```yaml
lightup:
  enabled: true
  domain: "gslb-sitetest.akadata.ltd."
  ttl: 60
  forward: true
  reverse: true
  strategy: "hash"

  families:
    - family: "ipv6"
      class: "public"
      prefix: "2a02:8012:bc57::/48"
      respond_aaaa: true
      respond_ptr: true
      exclude:
        - "2a02:8012:bc57:1::/64"
        - "2a02:8012:bc57:3::/64"
        - "2a02:8012:bc57:5::/64"
        - "2a02:8012:bc57:500::/64"
        - "2a02:8012:bc57:babe::/64"
        - "2a02:8012:bc57:baba::/64"
        - "2a02:8012:bc57:fead::/64"
        - "2a02:8012:bc57:f00d::/64"

    - family: "ipv6"
      class: "ula"
      prefix: "fd00:1234:5678::/48"
      respond_aaaa: true
      respond_ptr: true
      exclude: []

  forward_template: "{addr}.lit.gslb-sitetest.akadata.ltd."
  ptr_template: "lit-{net}-{region}-{host}.gslb-sitetest.akadata.ltd."

  ns_aaaa:
    - "2a02:8012:bc57:9000::1"
    - "2a02:8012:bc57:a000::1"
    - "2a02:8012:bc57:b000::1"
    - "2a02:8012:bc57:c000::1"
```

And where IPv4 is to be allowed later, the long-term shape is probably not prefix: alone, but a family-aware form such as:
```
lightup:
  enabled: true
  domains:
    - domain: "gslb-sitetest.akadata.ltd."
      prefixes:
        - cidr: "2a02:8012:bc57::/48"
          family: "ipv6"
          respond_aaaa: true
          respond_ptr: true
        - cidr: "172.22.0.0/24"
          family: "ipv4"
          respond_a: true
          respond_ptr: true
```

### Required work

* add config types
* add validation
* add tests for invalid prefix values
* add tests for invalid excludes
* add tests for overlapping or malformed entries

### Rule

Only one prefix at first. Only one strategy at first.

---

## Phase 3 — Forward AAAA Synthesis with ULA support

### Task

Implement synthesized AAAA answers for names inside a light-up zone when no real AAAA exists.

### Rules

* synthesize AAAA only in the first pass
* do not synthesize A records yet
* do not synthesize PTR yet
* ensure ULA is supported so we serve public private addresses
* do not synthesize over a configured record
* do not synthesize inside excluded prefixes
* use deterministic mapping so the same name always gets the same IPv6

### Suggested internal helper functions

* `LightupAddressForName(zone, fqdn) net.IP`
* `LightupNameAllowed(zone, fqdn) bool`
* `LightupIPExcluded(zone, ip) bool`

### Strategy

Use one deterministic strategy first:

* FNV64 or an existing stable hash
* write the low 64 bits into the host portion of the address
* preserve the configured prefix

### Tests

* same name always yields same IPv6
* different names yield different IPv6
* excluded prefixes are never returned
* configured AAAA always beats synthetic AAAA

---

## Phase 4 — Reverse PTR Synthesis

### Task

Add synthesized PTR support for light-up addresses.

### Rules

* only for addresses inside configured light-up prefix
* never for excluded prefixes
* never over a real configured PTR
* return a stable readable name derived from the IPv6

### First-pass PTR style

Keep it simple at first, for example:

* `lit-<compressed-ip>.<zone>`
* or `addr-<hex>.<zone>`

Do not attempt active / standby naming in the first PTR implementation.

### Tests

* PTR resolves only inside the lit range
* excluded ranges do not synthesize PTR
* real PTR beats synthetic PTR

---

## Phase 5 — DNSSEC on Synthesized Answers

### Task

Ensure synthetic AAAA and PTR answers pass through the existing DNSSEC signing path exactly like configured records.

### Requirements

* no separate signing path
* signed synthesized AAAA answers
* signed synthesized PTR answers
* NSEC and NSEC3 correctness preserved
* NXDOMAIN and NODATA behaviour preserved

### Tests

* DNSSEC-enabled light-up zone signs synthesized AAAA
* DNSSEC-enabled light-up zone signs synthesized PTR
* NSEC and NSEC3 tests still pass

This is a hard requirement, not a later nice-to-have.

---

## Phase 6 — Shared State and Replication

### Task

Ensure light-up config and behaviour replicate correctly across primary and secondary nodes.

### Requirements

* primary and secondary carry the same effective light-up config
* secondaries synthesize the same answers as primaries
* no node-specific drift
* serial handling remains correct
* zone transfers include enough state for deterministic synthesis

### Tests

* same lit name resolves identically on primary and secondary
* same PTR resolves identically on primary and secondary
* replication includes light-up config or equivalent authoritative state

Do not create a second replication model.

---

## Phase 7 — Local Policy and Geo Interaction

### Task

Ensure synthesized answers still pass through the same local-policy and geo logic already present.

### Requirements

* light-up does not bypass internal / external answer shaping
* RFC1918 and ULA-aware logic remains correct
* geo-aware logic does not break when synthesis is in use

### Tests

* internal and external clients still see correct policy outcomes
* geo-aware paths do not panic or mis-handle synthesized answers

The light-up layer must fit into existing policy logic, not bypass it.

---

## Phase 8 — State-Based Naming Layer

### Task

Only after forward and reverse synthesis are stable, add an optional naming layer that reflects live health state.

### Goal

Use reverse names to reflect state such as:

* active
* standby
* live

### Important boundary

Health drives routing. PTR reflects truth. PTR is not the control plane.

### Example optional config

```yaml
lightup:
  state_names: true
  active_label: "active"
  standby_label: "standby"
```

This phase is explicitly later work.

---

## Phase 9 — API and Web UI Exposure

### Task

After the DNS core is stable, expose light-up config and state through:

* the JSON / API layer
* the web UI
* validation screens

### UI/API should show

* prefix
* exclusions
* sample generated names
* sample generated PTRs
* whether DNSSEC is applied
* whether the zone replicates correctly

The UI is not the first implementation target. Core DNS behaviour comes first.

---

## Additional Desired Future Enhancements

These are not phase-1 requirements, but Codex should keep them in mind when designing the code:

* template-driven addressing such as `2a02:8012:bc57:<net>:<region>::<host>`
* health-aware active / standby reverse names
* integration with shared SQLite-backed config/state
* full API and WUI editing
* local-policy exposure in UI
* generated reverse naming based on role, region, and host identity

---

## Strict Rules for Codex

1. Do not break current authoritative zone serving.
2. Do not bypass DNSSEC.
3. Do not synthesize over real records.
4. Do not place light-up before configured or health-driven answers.
5. Do not add multiple strategies at first.
6. One prefix first. One strategy first. One test zone first.
7. Every phase must include tests.
8. Preserve replication and shared-state behaviour.
9. Preserve geo and local-policy behaviour.
10. Keep Mac and BSD portability in mind even where Linux is the first test platform.

---

## First Prompt for Codex

Start with this exact task:

Map the current answer path in BreathGSLB for AAAA and PTR queries, identify the correct insertion point for synthesized light-up answers after real and health-driven records, then add a new validated `lightup` zone config with one prefix, one exclude list, and tests only. Do not synthesize answers yet.

---

## Second Prompt for Codex

After the first phase is complete, continue with:

Implement synthesized AAAA answers for light-up zones using deterministic name-to-address mapping, with real records taking precedence, excluded prefixes blocked, and the existing DNSSEC path unchanged. Add tests.

---

## Final Thought

The old honeyDNS / networklightdns code already proved the lamp can be lit.

BreathGSLB is where the lamp becomes part of a real system.

The path is clear. The work is staged. The task is ready.

