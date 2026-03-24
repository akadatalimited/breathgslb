# BreathGSLB — AI Guide (Operator + Developer)

A compact authoritative **GSLB (Global Server Load Balancer)** written in Go using `miekg/dns`. BreathGSLB serves A/AAAA (plus TXT/MX/CAA/RP/SSHFP/SRV/NAPTR), steers traffic by **health** and optional **GeoIP**, supports **local/private views** (RFC1918/ULA), hot **SIGHUP reload**, **DNSSEC (alpha)** signing, EDNS/ECS, and multi-address binding.

This guide orients AI coding assistants (e.g., Codex, qwen3‑coder‑plus) and human operators. It explains how things work, how to run it, and the roadmap for multi‑tenant API, JWT, billing, and GDPR controls.

---

## 1) Core Concepts

### Zones & Answers

* Each delegated zone (e.g., `gslb‑example.example.`) is defined in YAML.
* Answers at the **apex** (owner == zone name) are health‑steered across three tiers:

  * **master** → preferred (fast site)
  * **standby** → secondary (reliable site)
  * **fallback** → last resort (optional)
* Per‑tier **private answers** and **CIDR allowlists** let local clients receive RFC1918/ULA while Internet clients receive public IPs.

### Health Model

* HTTPS probe to each configured IP (v4/v6 lists per tier).
* **rise / fall** counters, with **cooldown** (minimum dwell time before flipping state), and jittered intervals.
* Family‑specific: v4 can be UP while v6 is DOWN, and vice‑versa.

### Views (Global vs Local)

* `serve: "global"` → always public answers.
* `serve: "local"` → if client (or ECS subnet) is inside tier‑specific RFC/ULA CIDRs, return `*_private`; otherwise public.

### Geo Steering (Optional)

* If `geoip.enabled: true` with a MaxMind Country DB:

  * **Policy** (`geo:`) gates which tier is eligible per country/continent.
  * **Overrides** (`geo_answers:`) can directly return per‑country/continent A/AAAA and private answers (with their own RFC/ULA CIDRs).
* ECS (`+subnet` in `dig`) is honored when present.

### DNSSEC (Beta) with a green light, NSEC and NSEC3 is fully supported

* Loads BIND‑style KSK/ZSK from disk and signs DNSKEY + answer RRsets.
* Minimal NSEC for NXRRSET at the apex (full NXDOMAIN/NSEC3 is complete).

### Reload/Logging/Binding

* **Reload:** `SIGHUP` (OpenRC `reload` / systemd `ExecReload=`).
* **Logs:** file + stderr with simple, clean lines.
* **Binding:** `listen`, `listen_addrs`, or `interfaces` (auto‑discover addresses) across UDP/TCP, v4/v6.

---

## 2) Minimal YAML (annotated)

```yaml
listen: ":53"
listen_addrs: ["0.0.0.0:53", "[::]:53"]
interfaces: ["eth0", "ppp0"]

# Probes / EDNS
timeout_sec: 5
interval_sec: 8
rise: 2
fall: 4
cooldown_sec: 25
jitter_ms: 600
edns_buf: 1232
log_queries: true
log_file: "/var/log/breathgslb/breathgslb.log"

# Optional GeoIP
geoip:
  enabled: true
  database: "/etc/breathgslb/geoip/GeoLite2-Country.mmdb"
  prefer_field: "registered"   # or "country"
  cache_ttl_sec: 600

zones:
  - name: "gslb-sitetest.akadata.ltd."
    ns: ["ns-gslb.akadata.ltd."]
    admin: "hostmaster.akadata.ltd."
    ttl_soa: 60
    ttl_answer: 20

    serve: "local"
    private_allow_when_isolated: true

    # Public tiered answers
    a_master: ["217.155.241.55"]
    aaaa_master: ["2a02:8012:bc57::1"]
    a_standby: ["13.41.102.86"]
    aaaa_standby: ["2a05:d01c:65b:7100:f50:5bf:250c:dc5f"]

    # Local/private answers and their CIDRs per tier
    a_master_private:    ["172.16.0.1"]
    aaaa_master_private: ["2a02:8012:bc57:1::2"]
    rfc_master: ["172.16.0.0/24"]
    ula_master: ["2a02:8012:bc57:1::/64"]

    # Optional Geo policy (tier eligibility)
    geo:
      master:
        allow_countries: ["GB"]
        allow_continents: ["EU"]
      standby:
        allow_countries: ["US", "CA"]
      fallback:
        allow_all: true

    # Optional Geo per‑region answers
    geo_answers:
      country:
        GB:
          a: ["217.155.241.55"]
          aaaa: ["2a02:8012:bc57::1"]
          a_private: ["172.16.0.1"]
          aaaa_private: ["2a02:8012:bc57:1::2"]
          rfc: ["172.16.0.0/24"]
          ula: ["2a02:8012:bc57:1::/64"]
      continent:
        NA:
          a: ["13.41.102.86"]
          aaaa: ["2a05:d01c:65b:7100:f50:5bf:250c:dc5f"]

    # Shared/static records
    txt:
      - text: ["Breath Technology - a DNS Zone by BreathGSLB - In YHVH we trust"]
    mx:
      - preference: 1  exchange: "aspmx.l.google.com."
      - preference: 5  exchange: "alt1.aspmx.l.google.com."
    caa:
      - flag: 128 tag: issue value: "letsencrypt.org"

    # Health
    health:
      host_header: "gslb-sitetest.akadata.ltd"
      sni: "gslb-sitetest.akadata.ltd"
      path: "/health"
      insecure_tls: false

    # DNSSEC (Alpha)
    dnssec:
      enable: true
      zsk_keyfile: "/etc/breathgslb/keys/Kgslb-sitetest.akadata.ltd.+013+38151"
      ksk_keyfile: "/etc/breathgslb/keys/Kgslb-sitetest.akadata.ltd.+013+12218"
```

---

## 3) Operating Cheatsheet

**Start/Reload/Stop**

```sh
breathgslb -config /etc/breathgslb/config.yaml &
kill -HUP $(pidof breathgslb)    # reload
kill -TERM $(pidof breathgslb)   # stop
```

**Ask the auth directly**

```sh
dig @ns-gslb.akadata.ltd A gslb-sitetest.akadata.ltd +norecurse
dig @ns-gslb.akadata.ltd AAAA gslb-sitetest.akadata.ltd +dnssec +norecurse
```

**Demonstrate ECS/local view**

```sh
dig @ns-gslb.akadata.ltd +subnet=172.16.0.1/24 A gslb-sitetest.akadata.ltd +norecurse
```

**Trace**

```sh
dig +trace AAAA gslb-sitetest.akadata.ltd
```

---

## 4) Replication & Multi‑Master (Design)

BreathGSLB focuses on **authoritative answering with local health**. For broad HA:

* **Two independent authorities** (e.g., FTTP site + Cloud) both serve the delegated zone. Each follows the *same* YAML and keys (DNSSEC) and performs its own health probes.
* Public resolvers cache based on your TTLs; keep `ttl_soa` modest during maintenance.
* To minimize window during binary replacement, use a **secondary node** to keep serving while the primary restarts; prefer **reload** over restart when changing config.

**Multi‑Master considerations**

* SOA serials will diverge if each node unilaterally sets `Serial: now()`. For classic AXFR/IXFR masters/slaves you’d maintain a single writable zonefile. BreathGSLB signs dynamically and does not rely on BIND‑style zonefile serial arithmetic yet.
* Roadmap includes: optional **status/replication channel** (gRPC/HTTPS) to coordinate **shared serial**, health, and CSR‑style DNSSEC key rotation.

**Many slaves**

* If you still run BIND/Knot/NSD as secondaries, you can delegate to BreathGSLB as **hidden primary** and have a separate unsigned or pre‑signed zone for XFR. (Roadmap: TSIG‑signed XFRs with in‑memory keys.)

---

## 5) RFC1918/ULA, Public/Private Views

* Per‑tier `rfc_*` and `ula_*` (CIDR arrays) declare **where local answers are allowed**.
* If `serve: "local"` and client (or ECS subnet) is inside those CIDRs, return `*_private` records for that tier; otherwise return public.
* `private_allow_when_isolated: true` allows private answers even if that tier’s health is DOWN (useful during WAN isolation).

---

## 6) Record Types Supported

* **A**, **AAAA** (health/GEO steered at apex)
* **TXT**, **MX**, **CAA**, **RP**, **SSHFP**, **SRV**, **NAPTR** (static/shared; per‑name via `name:`)
* **ALIAS‑like** behavior via `alias:` (BreathGSLB resolves A/AAAA of the target and returns them at apex).

---

## 7) DNSSEC Notes (Alpha)

* Load KSK/ZSK from files (`.key` + `.private`), algorithm 13 recommended (ECDSAP256SHA256).
* Signs DNSKEY with KSK; other RRsets with ZSK.
* Minimal NSEC at apex for NXRRSET (full NXDOMAIN later).
* For the public Internet to validate with DO=1, **publish DS** at parent. Until then, use `delv` with a local trust anchor.

---

## 8) Security & Networking

* Bind UDP+TCP/53; open firewall accordingly (optionally by interface).
* No recursion (authoritative only). Refuses to act as a resolver.
* Health checks use HTTPS; can set SNI/Host for proper cert validation. `insecure_tls: false` is recommended in production.

---

## 9) Roadmap — Multi‑Tenant API, JWT, Billing, GDPR

### Goals

* Host many customer zones securely with per‑tenant isolation and access control.
* Automate onboarding, billing, and suspension/reinstatement without data loss.
* Provide full **GDPR** features: data export (portability) and right‑to‑erasure workflows.

### API Surface (proposed)

* **Auth**: OAuth2 Client Credentials or direct **JWT** signed by provider.

  * Tenants get a **Client ID** and **Client Secret**; exchange for JWT or sign JWT with per‑tenant key.
* **Resources**:

  * `/v1/tenants` (create/update/suspend/reactivate)
  * `/v1/zones` (CRUD; zone YAML; validation; dry‑run; staged apply with SIGHUP)
  * `/v1/keys/dnssec` (upload, list, rotate, attest)
  * `/v1/keys/tsig` (on‑the‑fly HMAC key minting, rotation; memory or disk persistence)
  * `/v1/health` (probe results, rise/fall counters, current state)
  * `/v1/geo` (MMDB status/version, cache metrics)
  * `/v1/metrics/queries` (per‑zone/tenant query counts, RCODEs, QTYPEs; rollups)
  * `/v1/audit` (who changed what, when; immutable logs)

### Authorization Model

* **JWT claims**: `sub` (tenant), `scope` (e.g., `zones:write zones:read keys:write metrics:read`), `exp`, `iat`.
* **RBAC**: roles like `owner`, `admin`, `billing`, `readOnly` with scope mapping.
* **Key Management**: Per‑tenant signing keys (JWK/JWKS). Optionally provider‑issued access tokens.

### Multi‑Tenancy & Data Isolation

* Each zone belongs to a tenant ID; configs, keys, and logs partitioned by tenant namespace on disk and in memory.
* API server and DNS engine processes separated; DNS runs least‑privileged with read‑only view of staged configs.
* **Staged Apply**: API writes a new versioned config under tenant/zone; engine reloads that version atomically.

### Billing & Suspension

* **Meters**: query counts, bandwidth estimates, health probe counts.
* **Plans**: tiered thresholds; overage alerts.
* **Suspension**: API flag per zone → engine returns `NXDOMAIN` or a suspension TXT at apex (operator choice). No config is deleted.
* **Reactivation**: clear flag; engine reloads; state resumes.

### GDPR Workflows

* **Right of Access/Portability**: `/v1/export` → signed ZIP with zone YAML, keys (if allowed), and logs filtered by tenant.
* **Right to Erasure**: `/v1/erase` → marks tenant for deletion; retention policy window elapses; secure wipe of data at rest; DS/delegation guidance provided to tenant.
* **Data Minimization**: query logs can be **IP‑hashed** or truncated; ECS details optional and redacted by default.

### API Security Hardening

* mTLS between API gateway and engine; JWT audience checking; short token TTLs; refresh via client credentials.
* Strict input validation (zone names FQDN, TXT length limits, CIDR parsing, etc.).
* Structured audit logs; tamper‑evident store (hash‑chained records).

---

## 10) Persistence & Load Balancing (Planned)

* **Persistence**: hash client subnet (from ECS when available, else source /24 or /56) to pick a stable IP within a tier’s list. Ensures session stickiness without server‑side state.
* **Weighted RR / Round‑Robin**: per‑address weights within a tier; health‑aware shuffling.

---

## 11) Tips for AI Coding Assistants

* Because it's 2026 and if we did not tell you your AI can help we would be living in the past.
* Keep examples **deterministic**: single‑line YAML changes per example.
* Prefer **small PR‑sized** patches; compile frequently (`go build`).
* Respect the current file split (`types.go`, `main.go`, etc.) when adding features; avoid canvas overflows by moving large helpers into new files (e.g., `geo.go`, `dnssec.go`).
* Use explicit imports; vendor third‑party modules if building in restricted environments.

---

## 12) License

We recommend **MIT License** for the core project; optional enterprise packaging can remain free while offering support SLAs.

---

## 13) Acknowledgments

* `miekg/dns` for DNS building blocks.
* MaxMind GeoLite2 for free Country database.

> Ship simply. Keep it observable. Glory to YHVH.

