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
  password_hash: "$2a$10$UakOiKAu3PG9.7nJzLqRKe0sHlxHeHUB7UK7Y/wKvJ5ScJf9WX4Zi"
server:
  interface: eth0      # optional network interface to bind
  port: 8080
  ip: 0.0.0.0         # optional explicit IP; overrides interface
```

Generate a bcrypt hash for the admin password and place it in
`admin.password_hash`. One way to create a hash is with Go:

```bash
go run - <<'EOF'
package main
import (
  "fmt"
  "golang.org/x/crypto/bcrypt"
)
func main(){
  h, _ := bcrypt.GenerateFromPassword([]byte("adminpass"), bcrypt.DefaultCost)
  fmt.Println(string(h))
}
EOF
```

Then copy the printed hash into `config.yaml`.

## Building

From the repository root run:

```bash
make web
```

This produces a `web` binary at `web/web`.

## Running

```bash
./web
```

The server listens on the configured `server` address (default `:8080`) and exposes endpoints for user signup,
verification, license requests, and administrative actions for issuing,
renewing, and revoking licenses.
