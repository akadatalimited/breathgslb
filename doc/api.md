# Admin API

BreathGSLB exposes optional HTTPS endpoints for health and runtime statistics.

## Enabling

Provide a listen address, token, and TLS certificate/key when launching the server.

### Linux/macOS

```sh
breathgslb -config /etc/breathgslb/config.yaml \
  -api-listen :9443 \
  -api-token $(cat /etc/breathgslb/token) \
  -api-cert /etc/breathgslb/cert.pem \
  -api-key /etc/breathgslb/key.pem
```

### Windows PowerShell

```powershell
breathgslb.exe -config C:\breathgslb\config.yaml `
  -api-listen :9443 `
  -api-token (Get-Content C:\breathgslb\token) `
  -api-cert C:\breathgslb\cert.pem `
  -api-key C:\breathgslb\key.pem
```

## Using the API

All requests require an `Authorization: Bearer <token>` header.

Endpoints:

- `GET /health` – current health status
- `GET /stats` – runtime statistics
- `GET /openapi.yaml` – OpenAPI specification
- `GET /swagger/` – interactive Swagger UI

Example request:

```sh
curl -H "Authorization: Bearer $TOKEN" https://localhost:9443/health
```

The same curl command works in PowerShell.
