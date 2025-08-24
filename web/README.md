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
public_signup: true   # set false to require admin to create accounts
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

If `public_signup` is set to `false`, the `/signup` endpoint returns `403` and
an authenticated administrator can create user accounts through the "Create
User" form linked from the admin dashboard.

## Admin Portal

An HTML admin portal is available for common management tasks. After
starting the server, visit `http://<host>:<port>/admin/login` to log in
with the configured administrator credentials. Successful login redirects
to `/admin`, which shows a simple dashboard linking to other admin
functions.

Licenses can be issued through the form at `/admin/license`. Static
assets like CSS are served from `/static/`, keeping presentation files
out of the Go source.
