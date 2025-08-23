# Licensing and Support Guide

## License fields

| Field | Description |
|-------|-------------|
| `build` | Build date tied to the license |
| `os` | Target operating system |
| `email` | Licensed contact address |
| `salt` | Unique value preventing replay |
| `expiry` | When the license ceases to be valid (`"never"` for perpetual) |
| `support_expiry` | Date when support coverage ends |
| `supported` | Whether support is currently active |
| `customer_type` | User type such as `community`, `basic`, `pro`, or `enterprise` |

## Supported vs. unsupported behaviour

**Supported**

- Using official releases on supported platforms
- Configuration within documented options
- Opening requests while support is active

**Unsupported**

- Running modified or unofficial binaries
- Relying on experimental or undocumented features
- Operating after `support_expiry`

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
./licensegen -email user@example.com -build 2024-05-01 -os linux \
  -supported -supportExpiry 2025-05-01 -customerType pro
```

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
