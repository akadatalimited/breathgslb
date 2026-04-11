#!/usr/bin/env bash
set -euo pipefail

dest="${1:-/etc/breathgslb}"
token_file="${dest}/api.token"
cert_file="${dest}/api.crt"
key_file="${dest}/api.key"

mkdir -p "${dest}"

if [[ ! -f "${token_file}" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32 > "${token_file}"
  else
    head -c 32 /dev/urandom | base64 > "${token_file}"
  fi
  chmod 0600 "${token_file}"
  echo "==> generated demo API token at ${token_file}"
else
  echo "==> keeping existing demo API token at ${token_file}"
fi

if [[ ! -f "${cert_file}" || ! -f "${key_file}" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate demo API TLS credentials" >&2
    exit 1
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  cat > "${tmpdir}/openssl.cnf" <<'EOF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
CN = breathgslb-demo-api
O = BreathGSLB Demo

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = gslb.zerodns.co.uk
DNS.3 = gslb2.zerodns.co.uk
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = 2a02:8012:bc57:53::1
IP.4 = 2a02:8012:bc57:53a::1
EOF

  openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -days 3650 \
    -keyout "${key_file}" \
    -out "${cert_file}" \
    -config "${tmpdir}/openssl.cnf"

  chmod 0600 "${key_file}"
  chmod 0644 "${cert_file}"
  echo "==> generated demo API certificate at ${cert_file}"
  echo "==> generated demo API key at ${key_file}"
else
  echo "==> keeping existing demo API TLS credentials at ${cert_file} and ${key_file}"
fi
