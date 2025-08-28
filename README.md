# BreathGSLB

A compact, authoritative, health‑checked GSLB that answers A/AAAA based on live
endpoint status, while also serving everyday
DNS records (TXT, MX, CAA, RP, SSHFP, SRV, NAPTR) and optional
ALIAS/ANAME‑like apex or hostname mapping.

> Goal: keep traffic on the big box with capacity when it’s healthy, fail over
to the reliable box when it’s not.
Minimal moving parts, RFC‑sane answers.

---

## Code layout

The main server logic resides in `main.go`.
Zone indexing utilities live in `zone_index.go`, and preflight
configuration validators are in `record_validate.go` so malformed records are
caught before runtime.

---

## Why this exists

Often there are two places to run a site:

* a smaller host with near‑perfect uptime but limited CPU, RAM, or bandwidth;
  and
* a larger host with plenty of headroom but a shakier last‑mile or ISP.

BreathGSLB lets the zone apex serve the “best” A/AAAA only when the capacity
host is passing health checks; otherwise the reliable host’s A/AAAA are
returned.
Flap damping (rise/fall counters), cooldown, and jitter keep answers steady
instead of chattering during short blips. At the same time,
the zone can publish normal records (TXT/MX/CAA/RP/SSHFP/SRV/NAPTR) so the
sub‑zone is fully useful, not just a raw IP switch.

DNSSEC is supported in both manual and generated modes. You can load existing
BIND‑style `zsk_keyfile`/`ksk_keyfile` prefixes or let BreathGSLB create and
persist the keys automatically. When both prefixes are the same (or
`ksk_keyfile` is omitted) generated keys are written with `.zsk` and `.ksk`
suffixes to keep files distinct—use unique prefixes if you intend to store
both pairs.

---

## Documentation

A combined manual and deployment guide is available as
[doc/breathgslb.pdf](doc/breathgslb.pdf). Release archives also include this PDF
for offline reference.

---

## Features

* **Authoritative only** for delegated sub‑zones (no recursion).
* **Health‑based A/AAAA** at the apex: direct HTTPS checks to literal IPs with
  SNI/Host header.
* **Flap damping**: rise/fall thresholds, **cooldown** window, and per‑check
  **jitter**.
* **Shared records**: TXT, MX, CAA, RP, SSHFP, SRV, NAPTR.
* **ALIAS/ANAME‑like mapping** for the apex or specific hostnames; apex used as a final fallback when all A/AAAA lists are empty.
* **EDNS0 buffer** respected (e.g., 1232 bytes for IPv6 safety).
* **Dual‑stack listeners** (udp4/udp6/tcp4/tcp6) on the chosen port.
* **TSIG ACLs**: zone transfers require TSIG by default. Signed requests are
  served only to client IPs listed in that key's `allow_xfr_from`; others receive
  `REFUSED`. Unsigned transfers may be enabled via configuration.
* **Syslog logging** with stderr fallback; cross‑platform binary (Linux, macOS,
  Windows, \*BSD).
* **DNS64 synthesis** lets IPv6‑only clients reach IPv4‑only zones.


---

## How it works

1. Parent zone delegates a sub‑zone (e.g., `gslb-sitetest.akadata.ltd.`) to `ns-
   gslb.akadata.ltd.` with glue.
2. BreathGSLB runs as an authoritative server for that sub‑zone only.
3. A/AAAA at the **apex** come from either the **healthy** set or the
   **fallback** set. Health is checked per IP using probes such as HTTP/HTTPS,
   HTTP/3, TCP, UDP, ICMP, or raw IP protocols, with optional body `expect`
   matching. If only A records exist, IPv6 clients receive synthesized AAAA
   answers via DNS64.
4. Rise/fall thresholds, cooldown, and jitter prevent rapid oscillation.
5. Other record types are served as configured.

---

## Quick start

### Build

Alpine:

```sh
apk add go git
cd /opt && git clone https://github.com/akadatalimited/breathgslb.git
cd breathgslb
go build -trimpath -ldflags "-s -w" -o breathgslb ./src
install -m 0755 breathgslb /usr/local/bin/breathgslb
setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
```

Arch:

```sh
pacman -S go git
cd /opt && git clone https://github.com/akadatalimited/breathgslb.git
cd breathgslb
go build -trimpath -ldflags "-s -w" -o breathgslb ./src
install -m 0755 breathgslb /usr/local/bin/breathgslb
setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
```

macOS/Windows/\*BSD: build with Go. If binding to port 53 is restricted, either
run elevated or use a higher port (e.g. `:5353`) and front with a
system‑specific port forward.

On Windows, paths use the native `C:` style. Build the executable and point to a
configuration file with Windows separators:

```powershell
go build -trimpath -ldflags "-s -w" -o breathgslb.exe ./src
./breathgslb.exe -config C:\breathgslb\config.yaml
```

The server relies on Go's `filepath` package, so `C:\` paths are handled
correctly.

Service installation examples for systemd, OpenRC, Windows, and macOS are
available in [doc/services.md](doc/services.md).

### License generator

An optional CLI can generate encrypted license payloads. Build it separately
with the `tools` tag:

```sh
go build -tags tools ./src/cmd/licensegen
```

It may also be run without producing a binary:

```sh
go run -tags tools ./src/cmd/licensegen -type trial
```

The `-type` flag presets support fields (choices: `trial`,
`standard`, `supported`). Remaining fields may be supplied via flags, a JSON
`-config` file, or will be prompted for interactively. When the `-send` flag is
used the generated license key is emailed to the requester.

The `-os` flag defaults to the host's platform and is case-insensitive but may
be provided to generate a license for another operating system.

Compiling `license.go` by itself will error because it depends on build-time
variables defined in `main.go`; build the entire server or the tool as shown
above.

### Delegate the sub‑zone

In the parent zone (e.g., at HE.net):

```
gslb-sitetest.akadata.ltd.  NS   ns-gslb.akadata.ltd.
ns-gslb.akadata.ltd.        A    <IPv4 of GSLB>
ns-gslb.akadata.ltd.        AAAA <IPv6 of GSLB>
```

TTL 300–900 is fine during testing.

### Health endpoint

On each origin, Nginx can respond:

```nginx
location = /health {
  access_log off;
  default_type text/plain;
  return 200 "OK\n";
}
```

Use valid TLS for the hostname being checked; during bootstrap, `insecure_tls:
true` is acceptable temporarily.

### Admin API

An optional HTTPS admin API serves health and runtime statistics. It can be
enabled either by supplying `-api-*` flags or by setting `api` options in
`config.yaml`. Detailed cross-platform instructions are available in
[doc/api.md](doc/api.md).

### Slave/Zone Transfers

Secondary servers may pull the zone over AXFR or IXFR. Allow the slave's IP in
`allow_xfr_from` and use the emitted key under `tsig.path` when signing
requests:

```sh
dig @203.0.113.10 example.net AXFR
dig @203.0.113.10 example.net AXFR -k /etc/breathgslb/keys/xfr-example.key
```

See [man/breathgslb.conf.5](man/breathgslb.conf.5) §“Slave/Zone Transfers” for
full details and IXFR examples.

---

## Configuration

Create `/etc/breathgslb/config.yaml` and run, supplying the base64‑encoded
license payload on first launch:

```
breathgslb -config /etc/breathgslb/config.yaml \
  -license-payload "$(cat /etc/breathgslb/license.payload)" \
  -metrics-listen :9090 \
  -supervisor /var/run/breathgslb.sock
```

The `-license-payload` flag provides the base64 string generated by
`licensegen`. After activation, the payload is saved to
`/etc/breathgslb/license.payload` and loaded automatically on subsequent runs,
so the flag can be omitted.

Add `-debug-pprof` to expose Go pprof handlers on `localhost:6060` for deep
inspection.

Sample configuration files and a full option reference are available in the
[`doc`](doc) directory.

### Global

```yaml
listen: ":53"           # server binds udp4/udp6/tcp4/tcp6 on this port
timeout_sec: 5           # per health probe
interval_sec: 8          # base interval between probe rounds
rise: 2                  # successes to mark UP
fall: 4                  # failures to mark DOWN
jitter_ms: 600           # add 0..600ms to each sleep
cooldown_sec: 25         # minimum seconds between flips (per A/AAAA family)
dns64_prefix: "64:ff9b::" # synthesize AAAA from A when needed
edns_buf: 1232           # EDNS0 UDP payload
log_queries: true
log_syslog: true
tsig:
  path: "/etc/breathgslb/tsig"
```

### Zone (example)

```yaml
zones:
  - name: "gslb-sitetest.akadata.ltd."
    ns: ["ns-gslb.akadata.ltd."]
    admin: "hostmaster.akadata.ltd."
    ttl_soa: 60
    ttl_answer: 20

    # Health‑driven apex addresses
    a_healthy:     ["217.155.241.55"]
    aaaa_healthy:  ["2a02:8012:bc57::1"]
    a_fallback:    ["13.41.102.86"]
    aaaa_fallback: ["2a05:d01c:65b:7100:f50:5bf:250c:dc5f"]

    # Optional ALIAS synth (only used if no A/AAAA lists are provided)
    # alias: "status.akadata.ltd."

    health:
      kind: http
      host_header: "gslb-sitetest.akadata.ltd"
      sni:         "gslb-sitetest.akadata.ltd"
      path:        "/health"
      expect:      "OK"
      insecure_tls: false
    # other kinds: http3, tcp (tls_enable:true, alpn: h2), udp, rawip (protocol:
    # 47)

    # Shared records (examples)
    txt:
      - text: ["openai-domain-verification=dv-EXAMPLE"]
        ttl: 300
      - name: "_dmarc.gslb-sitetest.akadata.ltd."
        text: ["v=DMARC1; p=quarantine; rua=mailto:postmaster@akadata.ltd"]
        ttl: 900

    mx:
      - preference: 1  ; exchange: "aspmx.l.google.com." ; ttl: 300
      - preference: 5  ; exchange: "alt1.aspmx.l.google.com." ; ttl: 300

    caa:
      - flag: 128 ; tag: "issue" ; value: "letsencrypt.org" ; ttl: 900
      - flag: 0   ; tag: "iodef" ; value: "mailto:abuse@akadata.ltd" ; ttl: 900

    rp:
      mbox: "hostmaster.akadata.ltd."
      txt:  "contact.akadata.ltd."
      ttl: 900

    sshfp:
      - algorithm: 4  # Ed25519
        type: 2      # SHA256
        fingerprint: "9F3C0B1E6A1D8A9B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6"
        ttl: 300

    srv:
      - name: "_sips._tcp.gslb-sitetest.akadata.ltd."
        priority: 10
        weight: 60
        port: 443
        target: "gslb-sitetest.akadata.ltd."
        ttl: 60

    naptr:
      - name: "gslb-sitetest.akadata.ltd."
        order: 100
        preference: 10
        flags: "S"
        services: "SIPS+D2T"
        regexp: ""
        replacement: "_sips._tcp.gslb-sitetest.akadata.ltd."
        ttl: 60
```

Supported `health.kind` values: `http`, `http3` (QUIC), `tcp`, `udp`, `icmp`,
and `rawip`.
Use `kind: tcp` with `tls_enable: true` and `alpn: "h2"` for HTTP/2 checks.
The optional `expect` field verifies a substring in the response body.
`path` defaults to `/health` only for `http` and `http3` probes.


**Trailing dots** are required for owner names that are absolute (NS, MX
exchanges, SRV targets, NAPTR replacements).
When `name` is omitted for TXT/MX/CAA/SSHFP/RP, the record is placed at the
apex.

---

## Integration tests

Optional integration tests exercise live zone transfers between BreathGSLB
instances. They require a `tests.config` file in the repository root specifying
the hosts involved. The file is YAML and ships with commented example values:

```yaml
# zone: example.org.
# tsig_name: gslb-xfr.
# tsig_secret: base64encodedsecret==
# primary: gslb-builder.breathtechnology.co.uk
# secondary: gslb-secondary.breathtechnology.co.uk
# standby: gslb-standby.breathtechnology.co.uk
# tester: gslb-tester.breathtechnology.co.uk
```

Uncomment and adjust these fields to match your environment. Tests automatically
skip when a required host is missing.

Run all tests with:

```sh
go test ./...
```

---

## Record‑type notes

### ALIAS (apex synth)

`alias` is evaluated only for the zone apex and comes into play only when all
`a_*`/`aaaa_*` lists are empty. In that case the server resolves the target and
returns its A/AAAA at the apex, acting as a final fallback.

Example:

```yaml
zones:
  - name: "alias-only.akadata.ltd."
    ns: ["ns-gslb.akadata.ltd."]
    admin: "hostmaster.akadata.ltd."
    alias: "status.akadata.ltd."
```

Sub‑domain host records (e.g., `www.alias-only.akadata.ltd.`) require
delegation to another DNS server.

### MX/CAA/RP/TXT

Standard static data. MX exchanges must be FQDNs. CAA `issue` and `iodef` common
values are shown above. RP publishes a responsible mailbox and a TXT pointer.

### SSHFP

Publishes SSH host key fingerprints so clients can verify hosts without TOFU
prompts.

**How to generate fingerprints:**

* From host public keys (common on servers):

  ```sh
  ssh-keygen -r gslb-sitetest.akadata.ltd -f /etc/ssh/ssh_host_ed25519_key.pub
  ```

  This prints SSHFP lines with algorithm/type and hex. Copy the hex value into
`fingerprint:`.
* Or list a key and convert:

  ```sh
  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
  ```

  Convert base64 SHA256 to hex if needed.

Algorithm numbers: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519, 6=Ed448. Type: 1=SHA1,
2=SHA256.

### SRV/NAPTR

Use service labels for SRV owners (e.g., `_sips._tcp.<zone>.`). Targets must be
FQDNs with trailing dots. NAPTR can point to SRV owners.
By pointing SRV/NAPTR targets to the apex, GSLB changes flow through naturally.

---

## Operations

### Run under a dedicated system user (`breathgslb`)

Create a non‑login service account, pre‑create config/log dirs, and run the
daemon as that user.

**Alpine (OpenRC)**

```sh
addgroup -S breathgslb
adduser -S -D -H -s /sbin/nologin -G breathgslb breathgslb

install -d -o breathgslb -g breathgslb -m 0750 /etc/breathgslb
install -d -o breathgslb -g breathgslb -m 0755 /var/log/breathgslb
# create or move your config, then
chown breathgslb:breathgslb /etc/breathgslb/config.yaml
chmod 0640 /etc/breathgslb/config.yaml

# allow binding to :53 without root
setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
apk add libcap
setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
install -d -o breathgslb -g breathgslb -m 0755 /var/log/breathgslb
install -d -o breathgslb -g breathgslb -m 0755  /etc/breathgslb/keys
chown -R breathgslb:breathgslb /etc/breathgslb/keys  # if DNSSEC keys live here
```

**Arch (systemd)**

```sh
groupadd --system breathgslb || true
useradd  --system --no-create-home \
        --gid breathgslb --home-dir /var/empty \
        --shell /usr/bin/nologin breathgslb || true

install -d -o breathgslb -g breathgslb -m 0750 /etc/breathgslb
install -d -o breathgslb -g breathgslb -m 0755 /var/log/breathgslb
chown breathgslb:breathgslb /etc/breathgslb/config.yaml
chmod 0640 /etc/breathgslb/config.yaml

setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
```

**systemd unit (Arch & other systemd hosts)**
Create `/etc/systemd/system/breathgslb.service`:

```ini
[Unit]
Description=BreathGSLB Authoritative DNS
After=network-online.target
Wants=network-online.target

[Service]
User=breathgslb
Group=breathgslb
# keep the capability minimal; binary also has file cap set
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStart=/usr/local/bin/breathgslb -config /etc/breathgslb/config.yaml
WorkingDirectory=/
Restart=on-failure

# Optional: let systemd ensure state/log dirs exist (v240+)
StateDirectory=breathgslb
LogsDirectory=breathgslb

[Install]
WantedBy=multi-user.target
```

Enable & start:

```sh
systemctl daemon-reload
systemctl enable --now breathgslb
journalctl -u breathgslb -f
```

**OpenRC service (Alpine)**
Create `/etc/init.d/breathgslb`:

```sh
#!/sbin/openrc-run
name="BreathGSLB"
description="Authoritative GSLB DNS"
command="/usr/local/bin/breathgslb"
command_args="-config /etc/breathgslb/config.yaml"
command_user="breathgslb:breathgslb"
pidfile="/run/breathgslb.pid"
supervisor="supervise-daemon"
output_log="/var/log/breathgslb/breathgslb.log"
error_log="/var/log/breathgslb/breathgslb.log"

depend() {
    need net
}

start_pre() {
    checkpath -d -o breathgslb:breathgslb -m 0755 /var/log/breathgslb
}
```

Then:

```sh
chmod +x /etc/init.d/breathgslb
rc-update add breathgslb default
rc-service breathgslb start
```

> Logs also go to stderr; enable `log_syslog` to emit to the local syslog
daemon.

### Windows service

On Windows (without WSL2), the executable can read configuration files from
native `C:` paths. Run an elevated PowerShell to install the service and open
firewall ports:

```powershell
go build -trimpath -ldflags "-s -w" -o C:\breathgslb\breathgslb.exe ./src
$bin = 'C:\breathgslb\breathgslb.exe -config C:\breathgslb\config.yaml'
New-Service -Name BreathGSLB `
  -BinaryPathName $bin `
  -DisplayName 'BreathGSLB' -StartupType Automatic
Start-Service BreathGSLB
netsh advfirewall firewall add rule name="BreathGSLB DNS UDP" dir=in `
  action=allow protocol=UDP localport=53
netsh advfirewall firewall add rule name="BreathGSLB DNS TCP" dir=in `
  action=allow protocol=TCP localport=53
netsh advfirewall firewall add rule name="BreathGSLB Metrics" dir=in `
  action=allow protocol=TCP localport=9090
```

—

### General ops

* **Run as non‑root** and grant low‑port bind:

  ```sh
  setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
  ```
* **Logs** default to `/var/log/breathgslb/breathgslb.log` and also emit to
  stderr. On systems without `/var/log` write access, logs fall back to
  `./breathgslb.log`.
* **Config changes**: restart the process to apply. (Hot reload can be added
  later.)
* **Firewall/SG**: open UDP/TCP 53 on IPv4+IPv6 to the world.

Basic troubleshooting:

```sh
# authoritative answers direct from your NS
dig @ns-gslb.akadata.ltd gslb-sitetest.akadata.ltd SOA +norecurse
dig @ns-gslb.akadata.ltd gslb-sitetest.akadata.ltd A    +norecurse

# TCP path (needed for large responses)
dig @ns-gslb.akadata.ltd gslb-sitetest.akadata.ltd A +tcp

# end‑to‑end trace
dig +trace gslb-sitetest.akadata.ltd A
```

* **Run as non‑root** and grant low‑port bind:

  ```sh
  setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
  ```
* **Logs** default to `/var/log/breathgslb/breathgslb.log` and also emit to
  stderr. On systems without `/var/log` write access, logs fall back to
  `./breathgslb.log`.
* **Config changes**: restart the process to apply. (Hot reload can be added
  later.)
* **Firewall/SG**: open UDP/TCP 53 on IPv4+IPv6 to the world.

Basic troubleshooting:

```sh
# authoritative answers direct from your NS
dig @ns-gslb.akadata.ltd gslb-sitetest.akadata.ltd SOA +norecurse
dig @ns-gslb.akadata.ltd gslb-sitetest.akadata.ltd A    +norecurse

# TCP path (needed for large responses)
dig @ns-gslb.akadata.ltd gslb-sitetest.akadata.ltd A +tcp

# end‑to‑end trace
dig +trace gslb-sitetest.akadata.ltd A
```

---

## Roadmap (next)

* **DNSSEC**: inline signing (ECDSA P‑256), DNSKEY/RRSIG and NSEC3, DS guidance
  for the parent.
* **Per‑record GSLB**: extend health‑based logic to selected sub‑names if
  required.
* **Weighted/geo policies**: optional weights or locality hints when multiple
  healthy addresses are present.
* **Admin API / SIGHUP reload**: configuration reload and simple metrics.

---

## Safety & scope

BreathGSLB is an authoritative nameserver for one or a few delegated zones. It
is not a recursive resolver and should not be exposed as such.
Keep TTLs conservative during early testing, and raise them once behaviour is
stable.

---

## Licensing & Support

BreathGSLB uses a simple license payload to gate features and track support
contracts. Licenses are permanent; only support agreements expire according to
`support_expiry`. After activation, the key and payload are stored in
`/etc/breathgslb/license` and `/etc/breathgslb/license.payload`, allowing future
runs without the `-license-payload` flag. Each license now includes only the
following fields:

| Field          | Purpose |
| -------------- | ------- |
| `os`           | Licensed operating system |
| `email`        | Contact for the licensed user |
| `salt`         | Random salt unique to the license |
| `support_expiry` | Support expiry date |
| `supported`    | `true` when a support contract is active |
| `customer_type` | Customer tier such as `personal`, `pro`, or `enterprise` (defaults to `personal`) |

### Supported behaviour

Help is provided for official binaries and documented configuration on
supported platforms. Running modified code, straying outside documented
behaviour, or operating without an active support contract is outside the
support scope.

### Requesting support

1. Verify your status with `licensectl -db path list`.
2. If support is active, open a ticket via the web service or email
   `support@example.com`.
3. Include logs, configuration, and the output of `licensectl` in the request.

### Web interface and CLI tools

Build the management tools and web interface from the repository root:

```sh
go build ./src/web              # license web service on :8080
go build ./src/cmd/licensegen   # issue new license payloads
go build ./src/cmd/licensectl   # list/revoke/regen keys
```

Run `./src/web/web` and visit `http://localhost:8080` to manage accounts and licenses.
Use `licensegen` with `-type` presets or a `-config` file to create payloads and
`licensectl` to manage stored keys.

### Support tiers (pricing placeholders)

| Tier       | Annual price |
|------------|--------------|
| Community  | $0 |
| Basic      | $X |
| Pro        | $Y |
| Enterprise | $Z |

See [doc/support.md](doc/support.md) for full details.

