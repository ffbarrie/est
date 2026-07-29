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

echo "Done. Try it with Docker:"
echo
echo "  docker run --rm -p 8443:8443 \\"
echo "    -v $OUT_DIR:/etc/estd:ro \\"
echo "    -v $OUT_DIR/data:/var/lib/estd:rw \\"
echo "    ghcr.io/ffbarrie/est:develop"
echo
echo "Then, from another terminal:"
echo
echo "  curl --cacert $OUT_DIR/server.crt https://localhost:8443/.well-known/est/cacerts"
