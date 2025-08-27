# Configuration

BreathGSLB is configured via a YAML file. Sample configurations are
provided in [`doc/examples`](examples).

Typical invocation:

```
breathgslb -config /etc/breathgslb/config.yaml
```

## Global Settings

| Key | Type | Description |
| --- | --- | --- |
| `listen` | string | Address or `:port` to bind; binds UDP/TCP on IPv4 and |
|          |        | IPv6. |
| `listen_addrs` | list[string] | Explicit `host:port` targets; overrides |
|                |              | `interfaces`. |
| `interfaces` | list[string] | Network interface names to derive bind |
|              |              | addresses. |
| `reverse_dir` | string | Directory where generated reverse zones are |
|               |        | written. |
| `timeout_sec` | int | Per‑probe timeout in seconds. |
| `interval_sec` | int | Base interval between probe rounds in seconds. |
| `rise` | int | Consecutive successes required to mark an endpoint UP. |
| `fall` | int | Consecutive failures required to mark an endpoint DOWN. |
| `jitter_ms` | int | Random jitter (milliseconds) added to each interval. |
| `cooldown_sec` | int | Minimum seconds between state flips for an |
|                |     | address family. |
| `dns64_prefix` | IPv6 prefix string | Prefix used when synthesizing AAAA |
|                |                     | from A. |
| `edns_buf` | int | Advertised EDNS0 UDP payload size; A/AAAA answers are |
|            |     | trimmed to fit. |
| `max_records` | int | Optional hard limit on A/AAAA records per response. |
| `log_queries` | bool | Log DNS queries and health transitions. |
| `max_workers` | int | Number of UDP worker goroutines. |
| `log_syslog` | bool | Send logs to syslog instead of stderr. |
| `tsig.path` | string | Directory containing TSIG key files. |
| `geoip.enabled` | bool | Enable GeoIP lookups. |
| `api` | bool | Enable HTTPS admin API. |
| `api-listen` | int | Port for admin API (default 9443). |
| `api-interface` | string or list[string] | Interface(s) to bind the admin |
|                 |                         | API. |
| `api-token` | string | Path to file containing bearer token or literal |
|             |        | token. |
| `api-cert` | string | TLS certificate for admin API. |
| `api-key` | string | TLS key for admin API. |

### GeoIP Block

| Key | Type | Description |
| --- | --- | --- |
| `geoip.database` | string | Path to a MaxMind‑style database. |
| `geoip.prefer_ecs` | bool | Trust EDNS Client Subnet when present. |
| `geoip.prefer_field` | string | `"country"` or `"registered_country"`. |
| `geoip.cache_ttl_sec` | int | LRU cache TTL for lookups. |

## Zones

`zones` is a list of zone definitions.

| Key | Type | Description |
| --- | --- | --- |
| `name` | FQDN string | Zone served authoritatively. |
| `ns` | list[FQDN] | Authoritative nameservers (parent must delegate). |
| `admin` | string | Administrator mailbox in dotted form. |
| `ttl_soa` | int | SOA record TTL. |
| `ttl_answer` | int | Default TTL for synthesized apex answers. |
| `refresh` | int | SOA refresh interval in seconds. |
| `retry` | int | SOA retry interval in seconds. |
| `expire` | int | SOA expire time in seconds. |
| `minttl` | int | SOA minimum/negative cache TTL. |
| `serve` | string | `"local"` to serve zone from this instance. |

### Address Pools

Apex A/AAAA answers come from the following lists. Each item may be a
plain IP string or an object with `ip` and optional `reverse` (bool) to
generate a reverse zone entry.

| Key | Value Type | Purpose |
| --- | --- | --- |
| `a_master`, `aaaa_master` | list[IPv4/IPv6 or map] | Primary pool returned |
|                           |                        | when healthy. |
| `a_standby`, `aaaa_standby` | list[IPv4/IPv6] | Used when master is |
|                             |                 | unhealthy. |
| `a_fallback`, `aaaa_fallback` | list[IPv4/IPv6] | Returned when master |
|                               |                 | and standby are down. |
| `rfc_master` | list[CIDR] | Private RFC1918 IPv4 ranges. |
| `a_master_private`, `aaaa_master_private` | list[IPv4/IPv6] | Internal‑only |
|                                           |                 | addresses. |
| `ula_master` | list[IPv6 prefix] | ULA/private IPv6 space. |
| `alias` | FQDN string | ALIAS‑like target when no A/AAAA lists exist. |

### Geographic Routing

`geoip` block mirrors the global GeoIP options.

`geo` block defines country/continent policies for pools:

- `master`, `standby`, `fallback` objects may contain:
  - `allow_countries` (list of ISO codes)
  - `allow_continents` (list of continent codes)
  - `allow_all` (bool)

### Health Checks

`health` describes how endpoints are probed.

Common field:

- `kind` (string): `http`, `http3`, `tcp`, `udp`, or `rawip`.
- `expect` (string): substring expected in the response.

Per kind options:

#### HTTP / HTTP3
- `host_header` (string)
- `sni` (string)
- `path` (string)
- `insecure_tls` (bool)

#### TCP
- `port` (int)
- `tls_enable` (bool)
- `sni` (string)
- `alpn` (string)

#### UDP
- `port` (int)
- `udp_payload_b64` (string) – base64 encoded probe payload.
- `udp_expect_re` (string) – regex to match the reply.

#### RAWIP
- `protocol` (int) – IP protocol number (e.g. 47 for GRE).

### DNSSEC

| Key | Type | Description |
| --- | --- | --- |
| `dnssec.mode` | string | DNSSEC mode: `off`, `manual`, or `generated`. |
| `dnssec.zsk_keyfile` | string | Path to ZSK key or prefix. |
| `dnssec.ksk_keyfile` | string | Path to KSK key or prefix. |

### TSIG

| Key | Type | Description |
| --- | --- | --- |
| `tsig.seed_env` | string | Environment variable name used to derive secrets. |
| `tsig.default_algorithm` | string or list[string] | Default HMAC algorithm |
|                          |                        | (`hmac-sha256`, etc.). |
| `tsig.keys` | list[map] | TSIG key definitions: `name` (FQDN), optional |
|             |           | `algorithm`, `secret` (string; empty ⇒ |
|             |           | derived), and `allow_xfr_from` (list[IP]). |

### Static Records

Optional sections add standard DNS records.

#### TXT
- `name` (string, optional; apex if omitted)
- `text` (list[string])
- `ttl` (int)

#### MX
- `preference` (int)
- `exchange` (FQDN)
- `ttl` (int)

#### CAA
- `flag` (int)
- `tag` (string)
- `value` (string)
- `ttl` (int)

#### RP
- `mbox` (FQDN)
- `txt` (FQDN)
- `ttl` (int)

#### SSHFP
- `name` (string, optional)
- `algorithm` (int)
- `typ` (int)
- `fingerprint` (hex string)
- `ttl` (int)

#### SRV
- `name` (string)
- `priority` (int)
- `weight` (int)
- `port` (int)
- `target` (FQDN)
- `ttl` (int)

#### NAPTR
- `name` (string)
- `order` (int)
- `preference` (int)
- `flags` (string)
- `service` (string)
- `regexp` (string)
- `replacement` (FQDN)
- `ttl` (int)

## DNS Record Types

- **A** – Maps a hostname to an IPv4 address.
- **AAAA** – Maps a hostname to an IPv6 address.
- **CNAME** – Alias pointing to a canonical name; not valid at the zone apex.
- **TXT** – Free‑form text; often used for verification and metadata.
- **MX** – Mail exchange records directing email for the domain.
- **CAA** – Certificate Authority Authorization; restricts which CAs may
  issue certificates.
- **RP** – Responsible Person contact information for the domain.
- **SSHFP** – SSH host key fingerprints for verifying SSH servers.
- **SRV** – Service location records specifying hosts and ports for
  particular services.
- **NAPTR** – Naming Authority Pointer used with SRV for
  application/service discovery.

Use record types appropriate to your deployment to remain compliant with DNS
RFCs.
