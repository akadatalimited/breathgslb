# NAME
breathgslb - health‑checked authoritative DNS with global load balancing
# SYNOPSIS
**breathgslb**
[ -config file ]
[ -api-listen addr ]
[ -api-token token ]
[ -api-cert file ]
[ -api-key file ]
[ -supervisor path ]
[ -debug-pprof ]
# DESCRIPTION
**BreathGSLB**
is a compact authoritative server that selects A and AAAA answers based on
live health checks.  It serves normal DNS records while optionally
synthesising AAAA from A via DNS64.  The daemon listens on UDP and TCP for
both IPv4 and IPv6 and can expose an HTTPS admin API for health and
statistics.
# DNS64
When no AAAA record exists for a name,
**breathgslb**
can synthesise one from an A record using the configured
**dns64_prefix .**
The IPv4 address is embedded into the prefix and returned to the
client, allowing an IPv6‑only host to reach a legacy IPv4 service via
an external NAT64 gateway.

Client AAAA?  -> BreathGSLB ->  A?   -> IPv4 server
       <- AAAA   DNS64      <-  A   <-
This bridges IPv6‑only networks to IPv4 infrastructure without exposing
new public addresses.
# OPTIONS
## -config " " file
Path to the YAML configuration file.  Defaults to
## -api-listen " " addr
Bind address for the optional HTTPS admin API, e.g.
**:9443**
or
127.0.0.1:9443 .
## -api-token " " token
Bearer token for API requests.  May be a literal string or
path to a file whose contents are used.
## -api-cert " " file
TLS certificate file for the admin API.
## -api-key " " file
TLS private key for the admin API.
## -supervisor " " path
Send service state change notifications to the given supervisor socket
or FIFO.  The format of the messages is supervisor specific.
## -debug-pprof
Enable Go's pprof debug server on
localhost:6060 .
# USAGE
Start the daemon with a configuration file:

breathgslb -config /etc/breathgslb/config.yaml

For split‑horizon deployments run separate instances with differing
configuration files and distinct listeners.  Share TSIG keys between
instances when signed zone transfers are required.

TLS certificates and API tokens are read from the paths supplied on the
command line or in the configuration file.  To rotate them atomically,
write the new material to a separate file, update a symlink, and reload
**breathgslb**
with
**SIGHUP**
or a restart.
# SEE ALSO
breathgslb.conf (5)