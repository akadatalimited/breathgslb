# Licensing and Support Guide

## License fields

Licenses are permanent; only support contracts expire as indicated by
`support_expiry`.

| Field | Description |
|-------|-------------|
| `os` | Licensed operating system |
| `email` | Licensed contact address |
| `salt` | Random salt unique to the license |
| `support_expiry` | Support expiry date |
| `supported` | Whether support is currently active |
| `customer_type` | User type such as `personal`, `pro`, or `enterprise` (defaults to `personal`) |

After a license is activated, the key is stored in `/etc/breathgslb/license` and
the base64 payload in `/etc/breathgslb/license.payload`. The daemon reads the
payload from that file automatically if the `-license-payload` flag is omitted.

## Supported vs. unsupported behaviour

**Supported**

- Using official releases on supported platforms
- Configuration within documented options
- Opening requests while support is active

**Unsupported**

- Running modified or unofficial binaries
- Relying on experimental or undocumented features
- Operating without a valid support contract

## Support request flow

1. Verify coverage:
   ```sh
   go build ./cmd/licensectl
   ./licensectl -db web.db list
   ```
2. Gather logs and configuration.
3. If covered, open `http://localhost:8080/support` or email `support@example.com`.
4. Track responses through the web UI or email.

## Web interface usage

Build and run the service:

```sh
go build ./web
./web
```

Visit `http://localhost:8080` to create accounts, request licenses, and file support tickets.

## CLI tools

### licensegen

```sh
go build ./cmd/licensegen
./licensegen -type supported -send -from sales@example.com
```

The `-type` flag presets support values (`trial`, `standard`,
`supported`). Missing fields like email and support status are read from
flags, a JSON `-config` file, or prompted for interactively. When `-send` is
specified the generated key is emailed to the requester. The optional,
case-insensitive `-os` flag defaults to the current platform but may be set to
issue a license for another operating system.

### licensectl

```sh
go build ./cmd/licensectl
./licensectl -db web.db list
./licensectl -db web.db revoke <key>
./licensectl -db web.db regen <key>
```

## Support tiers (pricing placeholders)

| Tier | Description | Annual price |
|------|-------------|--------------|
| Community | Community support via issue tracker | $0 |
| Basic | Email support, 48h response | $X |
| Pro | Priority email, 24h response | $Y |
| Enterprise | Dedicated channel, SLA | $Z |
