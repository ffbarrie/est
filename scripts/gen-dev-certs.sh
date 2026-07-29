#!/usr/bin/env bash
# Generates a throwaway test CA, server cert, and client cert for local
# testing of estd (including the Docker image) — the same recipe used by
# hand for every manual end-to-end verification pass of this server.
#
# Usage: scripts/gen-dev-certs.sh [output-dir]
#   output-dir defaults to ./.devcerts (gitignored).
#
# Writes ca.{key,crt}, server.{key,crt}, client.{key,crt}, and a matching
# config.json (with store_dir under <output-dir>/data) into output-dir.

set -euo pipefail

OUT_DIR="${1:-./.devcerts}"
mkdir -p "$OUT_DIR/data"
OUT_DIR="$(cd "$OUT_DIR" && pwd)" # absolute path, needed for config.json

echo "Generating dev certs in $OUT_DIR ..."

# Root CA — signs both the server cert and the client cert, and doubles as
# the issuing CA estd uses to sign certificates it enrolls.
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout "$OUT_DIR/ca.key" -out "$OUT_DIR/ca.crt" \
  -days 3650 -subj "/CN=estd Dev Root CA" 2>/dev/null

# Server TLS cert (SAN'd for localhost, since that's what dev clients connect to).
openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr" \
  -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$OUT_DIR/server.csr" \
  -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$OUT_DIR/server.crt" -days 825 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null
rm -f "$OUT_DIR/server.csr"

# Client cert for mTLS-authenticated /simpleenroll and /simplereenroll.
openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/client.key" -out "$OUT_DIR/client.csr" \
  -subj "/CN=dev-client.example.test" 2>/dev/null
openssl x509 -req -in "$OUT_DIR/client.csr" \
  -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$OUT_DIR/client.crt" -days 365 2>/dev/null
rm -f "$OUT_DIR/client.csr"

cat > "$OUT_DIR/config.json" <<EOF
{
  "listen_addr": "0.0.0.0:8443",
  "server_cert_file": "/etc/estd/server.crt",
  "server_key_file": "/etc/estd/server.key",
  "client_ca_files": ["/etc/estd/ca.crt"],
  "ca_cert_file": "/etc/estd/ca.crt",
  "ca_key_file": "/etc/estd/ca.key",
  "store_dir": "/var/lib/estd",
  "cert_validity": "8760h"
}
EOF

# A second, throwaway openssl-ca(1) CA directory (index.txt/serial/newcerts),
# reusing the same root CA key/cert generated above, for testing
# "ca_backend": "openssl" (internal/ca/openssl) locally. The est_extensions
# shape here (copy_extensions=copy + a fixed extensions section) is the same
# one verified in internal/ca/openssl's tests and documented in
# openssl-ca.example.cnf at the repo root — see that file for why it's safe.
OPENSSL_CA_DIR="$OUT_DIR/openssl-ca"
mkdir -p "$OPENSSL_CA_DIR/newcerts"
touch "$OPENSSL_CA_DIR/index.txt"
echo "unique_subject = no" > "$OPENSSL_CA_DIR/index.txt.attr"
echo 1000 > "$OPENSSL_CA_DIR/serial"
cp "$OUT_DIR/ca.crt" "$OPENSSL_CA_DIR/ca.crt"
cp "$OUT_DIR/ca.key" "$OPENSSL_CA_DIR/ca.key"

cat > "$OPENSSL_CA_DIR/openssl.cnf" <<EOF
[ca]
default_ca = est_ca

[est_ca]
dir             = $OPENSSL_CA_DIR
database        = \$dir/index.txt
serial          = \$dir/serial
new_certs_dir   = \$dir/newcerts
certificate     = \$dir/ca.crt
private_key     = \$dir/ca.key
default_md      = sha256
default_days    = 365
policy          = est_policy
copy_extensions = copy
x509_extensions = est_extensions

[est_policy]
commonName = supplied

[est_extensions]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

cat > "$OUT_DIR/config-openssl.json" <<EOF
{
  "listen_addr": "0.0.0.0:8443",
  "server_cert_file": "/etc/estd/server.crt",
  "server_key_file": "/etc/estd/server.key",
  "client_ca_files": ["/etc/estd/ca.crt"],
  "ca_cert_file": "/etc/estd/ca.crt",
  "store_dir": "/var/lib/estd",
  "cert_validity": "8760h",
  "ca_backend": "openssl",
  "openssl_ca": {
    "config_file": "/etc/estd/openssl-ca/openssl.cnf"
  }
}
EOF

echo "Done. Try it with Docker (default local, crypto/x509-based CA backend):"
echo
echo "  docker run --rm -p 8443:8443 \\"
echo "    -v $OUT_DIR:/etc/estd:ro \\"
echo "    -v $OUT_DIR/data:/var/lib/estd:rw \\"
echo "    ghcr.io/ffbarrie/est:develop"
echo
echo "...or with the openssl-backed CA (config-openssl.json + openssl-ca/, generated alongside"
echo "config.json above), overriding the default config path:"
echo
echo "  docker run --rm -p 8443:8443 \\"
echo "    -v $OUT_DIR:/etc/estd:ro \\"
echo "    -v $OUT_DIR/data:/var/lib/estd:rw \\"
echo "    ghcr.io/ffbarrie/est:develop -config /etc/estd/config-openssl.json"
echo
echo "Then, from another terminal, either way:"
echo
echo "  curl --cacert $OUT_DIR/server.crt https://localhost:8443/.well-known/est/cacerts"
