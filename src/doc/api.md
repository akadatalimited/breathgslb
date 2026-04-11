# Admin API

BreathGSLB exposes optional HTTPS endpoints for health and runtime statistics.

## Enabling

Add the following to `config.yaml`:

```yaml
api: true
api-listen: 9443
api-interface: ["eth0"]          # optional
api-token: "/etc/breathgslb/api.token"   # Windows: C:\\breathgslb\\api.token
api-cert: "/etc/breathgslb/api.crt"      # Windows: C:\\breathgslb\\api.crt
api-key: "/etc/breathgslb/api.key"       # Windows: C:\\breathgslb\\api.key
```

Start the server with:

```sh
breathgslb -config /etc/breathgslb/config.yaml
```

### Alternative: command-line flags

```sh
breathgslb -config /etc/breathgslb/config.yaml \
  -api-listen :9443 \
  -api-token /etc/breathgslb/api.token \
  -api-cert /etc/breathgslb/api.crt \
  -api-key /etc/breathgslb/api.key
```

On Windows PowerShell:

```powershell
breathgslb.exe -config C:\breathgslb\config.yaml `
  -api-listen :9443 `
  -api-token C:\breathgslb\api.token `
  -api-cert C:\breathgslb\api.crt `
  -api-key C:\breathgslb\api.key
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
