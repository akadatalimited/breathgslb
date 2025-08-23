# Web License Service

This directory contains a simple Go web application that manages license keys
using SQLite (configurable for MySQL).

## Configuration

Copy `config.example.yaml` to `config.yaml` and adjust the values:

```yaml
db:
  driver: sqlite # or mysql
  dsn: web.db      # for mysql use user:pass@tcp(host:3306)/dbname
admin:
  email: admin@example.com
```

## Building

From the repository root run:

```bash
go build ./web
```

This produces a `web` binary.

## Running

```bash
./web
```

The server listens on `:8080` and exposes endpoints for user signup,
verification, license requests, and administrative actions.
