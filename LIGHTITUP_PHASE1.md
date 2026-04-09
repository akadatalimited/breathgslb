# Light-Up Phase 1 Design Note

## Current AAAA Path

`authority.handle()` dispatches AAAA queries in [src/dns_functions.go](/tank/breathtechnology/breathgslb/src/dns_functions.go#L149) by calling `a.addrAAAA(name, cIP, r)`. Inside `addrAAAA()`, the live order is:

1. subdomain `alias_host` lookup
2. apex local-policy selection
3. apex geo answer override
4. apex geo policy tier pick
5. apex health-driven master/standby/fallback selection
6. DNS64 fallback
7. shared negative-response path back in `handle()`

The safest future insertion point for synthesized AAAA is after `addrAAAA()` returns no records and before the negative-response block at [src/dns_functions.go](/tank/breathtechnology/breathgslb/src/dns_functions.go#L174). That preserves EDNS, truncation, SOA/NXDOMAIN handling, and the common DNSSEC signing tail. If synthesis later needs client-sensitive ULA/public policy, it should be called from `addrAAAA()` only after the existing local/geo/health paths are exhausted.

## Current PTR Path

There is no live `dns.TypePTR` request path in [src/dns_functions.go](/tank/breathtechnology/breathgslb/src/dns_functions.go#L149). Current reverse support is config-time only: `GenerateReverseZones()` writes PTR YAML fragments under `reverse_dir` in [src/config/reverse.go](/tank/breathtechnology/breathgslb/src/config/reverse.go#L34). `Load()` then validates config and calls that generator at [src/config/load.go](/tank/breathtechnology/breathgslb/src/config/load.go#L52), but it only auto-loads `.fwd.yaml` zone files from `zones_dir` at [src/config/load.go](/tank/breathtechnology/breathgslb/src/config/load.go#L27). Today, generated reverse data is not part of the runtime answer path unless wired separately.

## DNSSEC, Index, and Replication Constraints

The common DNSSEC signing hook is the final `signAll()` pass in [src/dns_functions.go](/tank/breathtechnology/breathgslb/src/dns_functions.go#L227). Synthetic AAAA/PTR must reuse that path. Negative answers rely on `zidx.hasName()` and NSEC/NSEC3 proofs in [src/dns_functions.go](/tank/breathtechnology/breathgslb/src/dns_functions.go#L174) plus the configured-name index built in [src/util_functions.go](/tank/breathtechnology/breathgslb/src/util_functions.go#L13), so future synthetic owners will need explicit index/denial handling.

Secondary serving is a separate path at [src/dns_functions.go](/tank/breathtechnology/breathgslb/src/dns_functions.go#L71) backed by transferred RRsets from [src/authority_functions.go](/tank/breathtechnology/breathgslb/src/authority_functions.go#L60). Light-up must not be added only to the primary path or secondaries will drift immediately.

## Phase-1 Guardrail

`buildA()` and `buildAAAA()` currently hardcode the zone apex owner in [src/dns_functions.go](/tank/breathtechnology/breathgslb/src/dns_functions.go#L655). Future light-up answers for non-apex names or PTR owners must use owner-aware builders instead of reusing those helpers unchanged.
