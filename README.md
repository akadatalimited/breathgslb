# BreathGSLB

A compact, authoritative, health‑checked GSLB that answers A/AAAA based on live endpoint status, while also serving everyday 
DNS records (TXT, MX, CAA, RP, SSHFP, SRV, NAPTR) and an optional ALIAS/ANAME‑like apex.

> Goal: keep traffic on the big box with capacity when it’s healthy, fail over to the reliable box when it’s not. 
Minimal moving parts, RFC‑sane answers.

---

## Why this exists

Often there are two places to run a site:

* a smaller host with near‑perfect uptime but limited CPU, RAM, or bandwidth; and
* a larger host with plenty of headroom but a shakier last‑mile or ISP.

BreathGSLB lets the zone apex serve the “best” A/AAAA only when the capacity host is passing health checks; otherwise the reliable host’s A/AAAA are returned. 
Flap damping (rise/fall counters), cooldown, and jitter keep answers steady instead of chattering during short blips. At the same time, 
the zone can publish normal records (TXT/MX/CAA/RP/SSHFP/SRV/NAPTR) so the sub‑zone is fully useful, not just a raw IP switch.

DNSSEC is planned next; the codebase keeps the path clear for inline signing.

---

## Features

* **Authoritative only** for delegated sub‑zones (no recursion).
* **Health‑based A/AAAA** at the apex: direct HTTPS checks to literal IPs with SNI/Host header.
* **Flap damping**: rise/fall thresholds, **cooldown** window, and per‑check **jitter**.
* **Shared records**: TXT, MX, CAA, RP, SSHFP, SRV, NAPTR.
* **ALIAS/ANAME‑like apex** synth when no A/AAAA lists are set.
* **EDNS0 buffer** respected (e.g., 1232 bytes for IPv6 safety).
* **Dual‑stack listeners** (udp4/udp6/tcp4/tcp6) on the chosen port.
* **File logging** with fallback; cross‑platform binary (Linux, macOS, Windows, \*BSD).

---

## How it works

1. Parent zone delegates a sub‑zone (e.g., `gslb-sitetest.akadata.ltd.`) to `ns-gslb.akadata.ltd.` with glue.
2. BreathGSLB runs as an authoritative server for that sub‑zone only.
3. A/AAAA at the **apex** come from either the **healthy** set or the **fallback** set. Health is checked by literal IP using HTTPS to `/health` with proper Host/SNI.
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
go build -trimpath -ldflags "-s -w" -o breathgslb
install -m 0755 breathgslb /usr/local/bin/breathgslb
setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
```

Arch:

```sh
pacman -S go git
cd /opt && git clone https://github.com/akadatalimited/breathgslb.git
cd breathgslb
go build -trimpath -ldflags "-s -w" -o breathgslb
install -m 0755 breathgslb /usr/local/bin/breathgslb
setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
```

macOS/Windows/\*BSD: build with Go. If binding to port 53 is restricted, either run elevated or use a higher port (e.g. `:5353`) and front with a system‑specific port forward.

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
location = /health { access_log off; default_type text/plain; return 200 "OK\n"; }
```

Use valid TLS for the hostname being checked; during bootstrap, `insecure_tls: true` is acceptable temporarily.

---

## Configuration

Create `/etc/breathgslb/config.yaml` and run `breathgslb -config /etc/breathgslb/config.yaml`.

### Global

```yaml
listen: ":53"           # server binds udp4/udp6/tcp4/tcp6 on this port
timeout_sec: 5           # per health probe
interval_sec: 8          # base interval between probe rounds
rise: 2                  # successes to mark UP
fall: 4                  # failures to mark DOWN
jitter_ms: 600           # add 0..600ms to each sleep
cooldown_sec: 25         # minimum seconds between flips (per A/AAAA family)
edns_buf: 1232           # EDNS0 UDP payload
log_queries: true
log_file: "/var/log/breathgslb/breathgslb.log"
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
      host_header: "gslb-sitetest.akadata.ltd"
      sni:         "gslb-sitetest.akadata.ltd"
      path:        "/health"
      insecure_tls: false

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

**Trailing dots** are required for owner names that are absolute (NS, MX exchanges, SRV targets, NAPTR replacements). 
When `name` is omitted for TXT/MX/CAA/SSHFP/RP, the record is placed at the apex.

---

## Record‑type notes

### ALIAS (apex synth)

If `alias:` is set and no A/AAAA lists are defined, the server resolves the target using the host resolver and returns its A/AAAA at the apex. 
This is useful when another hostname should drive the addressing but a CNAME at the apex would be illegal.

### MX/CAA/RP/TXT

Standard static data. MX exchanges must be FQDNs. CAA `issue` and `iodef` common values are shown above. RP publishes a responsible mailbox and a TXT pointer.

### SSHFP

Publishes SSH host key fingerprints so clients can verify hosts without TOFU prompts.

**How to generate fingerprints:**

* From host public keys (common on servers):

  ```sh
  ssh-keygen -r gslb-sitetest.akadata.ltd -f /etc/ssh/ssh_host_ed25519_key.pub
  ```

  This prints SSHFP lines with algorithm/type and hex. Copy the hex value into `fingerprint:`.
* Or list a key and convert:

  ```sh
  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
  ```

  Convert base64 SHA256 to hex if needed.

Algorithm numbers: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519, 6=Ed448. Type: 1=SHA1, 2=SHA256.

### SRV/NAPTR

Use service labels for SRV owners (e.g., `_sips._tcp.<zone>.`). Targets must be FQDNs with trailing dots. NAPTR can point to SRV owners. 
By pointing SRV/NAPTR targets to the apex, GSLB changes flow through naturally.

---

## Operations

### Run under a dedicated system user (`breathgslb`)

Create a non‑login service account, pre‑create config/log dirs, and run the daemon as that user.

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

> Logs also go to stderr; the binary writes to the path configured by `log_file` (default `/var/log/breathgslb/breathgslb.log`).

—

### General ops

* **Run as non‑root** and grant low‑port bind:

  ```sh
  setcap 'cap_net_bind_service=+ep' /usr/local/bin/breathgslb
  ```
* **Logs** default to `/var/log/breathgslb/breathgslb.log` and also emit to stderr. On systems without `/var/log` write access, logs fall back to `./breathgslb.log`.
* **Config changes**: restart the process to apply. (Hot reload can be added later.)
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
* **Logs** default to `/var/log/breathgslb/breathgslb.log` and also emit to stderr. On systems without `/var/log` write access, logs fall back to `./breathgslb.log`.
* **Config changes**: restart the process to apply. (Hot reload can be added later.)
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

* **DNSSEC**: inline signing (ECDSA P‑256), DNSKEY/RRSIG and NSEC3, DS guidance for the parent.
* **Per‑record GSLB**: extend health‑based logic to selected sub‑names if required.
* **Weighted/geo policies**: optional weights or locality hints when multiple healthy addresses are present.
* **Admin API / SIGHUP reload**: configuration reload and simple metrics.

---

## Safety & scope

BreathGSLB is an authoritative nameserver for one or a few delegated zones. It is not a recursive resolver and should not be exposed as such. 
Keep TTLs conservative during early testing, and raise them once behaviour is stable.

