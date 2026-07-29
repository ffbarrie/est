# est

An [EST](https://www.rfc-editor.org/rfc/rfc7030) (Enrollment over Secure Transport) server, written in Go. It issues
and renews X.509 certificates over mutual TLS. The CA backend is pluggable behind a small interface; the only
implementation today is a local, in-process CA built on `crypto/x509` (no `openssl` CLI dependency).

## Status

- **Endpoints implemented:** `GET /cacerts`, `POST /simpleenroll`, `POST /simplereenroll`, `GET /csrattrs`.
- **Not implemented:** `/fullcmc`, `/serverkeygen` (no concrete need for them yet; both interfaces are small enough
  to extend without a redesign).
- **Auth:** mutual TLS only, for every endpoint. `/cacerts` and `/csrattrs` accept an anonymous connection (no client
  certificate) per RFC 7030 — that's their bootstrap use case. `/simpleenroll` and `/simplereenroll` require a client
  certificate the server already trusts.
- **CA backend:** local (`crypto/x509`-based) only, for now. A second backend (e.g. EJBCA) can be added as a sibling
  package implementing the same `ca.CABackend` interface, with no changes to the HTTP layer.
- **Storage:** issued certificates and CSRs are written to local files (see `internal/store`) — a deliberate
  placeholder, expected to be swapped for something heavier later.

Relevant RFCs, in the order they matter here: RFC 7030 (the base EST spec), RFC 8951 (clarifies base64 encoding and
retires the `Content-Transfer-Encoding` header), RFC 9908 (clarifies and extends the `/csrattrs` response format).

## Build & test

```bash
go build ./...
go test ./... -race
gofmt -l .   # should print nothing
go vet ./...
```

No external dependencies (`go.mod` has none) — this is deliberate, not an oversight; see `AGENTS.md`.

## Running it

```bash
go build -o estd ./cmd/estd
./estd -config config.json
```

`config.json` is a JSON file — see [config.example.json](config.example.json) for a fully worked example, and the
field reference below.

### Config fields

| Field | Required | Meaning |
|---|---|---|
| `listen_addr` | yes | Address to listen on, e.g. `"0.0.0.0:8443"` |
| `server_cert_file` / `server_key_file` | yes | The server's own TLS certificate/key (PEM) |
| `client_ca_files` | yes | PEM bundle(s) of CA certificates trusted for client mTLS |
| `ca_cert_file` / `ca_key_file` | yes | The issuing CA's certificate/key (PEM) — signs every certificate this server issues |
| `store_dir` | yes | Directory where issued certificates and CSRs are persisted |
| `cert_validity` | yes | Validity duration given to every issued certificate, e.g. `"8760h"` |
| `csr_attrs` | no | Configures the `GET /csrattrs` response; omit entirely for a `204` response |

`csr_attrs` supports two mechanisms, and both are documented in `config.example.json`:

- **Classic attributes** (`challenge_password`, `key_algorithm`, `required_extensions`, `extra_oids`): a list of OIDs
  and attributes the server wants the client to include in its CSR (RFC 7030 §4.5.2, as clarified by RFC 9908 §3.2).
- **Template** (`template`): a partially filled-in CSR — a subject DN with some RDNs dictated and others left blank,
  a key-type constraint, and extension values that may be partially specified — per RFC 9908 §3.4. The template's
  key-type constraint only supports EC (`curve_oid`); an RSA size requirement should use the top-level
  `key_algorithm` instead (see the doc comment on `csrattrs.Template.KeyType` for why).

`value_hex` fields throughout `csr_attrs` are raw, hex-encoded DER bytes — the server has no notion of what's inside
an extension's value; it just places the bytes you give it.

## Running via Docker

Images are built from the [Dockerfile](Dockerfile) (multi-stage, `CGO_ENABLED=0`, a distroless
`nonroot` final image — no shell, no package manager, runs as uid/gid `65532`) and published to
`ghcr.io/ffbarrie/est` on every merge to `develop` (tag `develop`) and `main` (tags `latest` and `main`), always
alongside a `sha-<short-commit>` tag.

```bash
docker pull ghcr.io/ffbarrie/est:develop
# or build locally:
docker build -t estd:dev .
```

The image expects config and certs mounted **read-only** at `/etc/estd/` (matching `config.example.json`'s layout)
and `store_dir` mounted **read-write** at `/var/lib/estd/`. Since the image runs as a fixed non-root uid, the host
directory backing the read-write mount needs to be writable by uid `65532` before the first run:

```bash
mkdir -p ./data && chown 65532:65532 ./data   # or: chmod a+rwX ./data for a quick local test
```

For a quick local try with throwaway dev certs, [scripts/gen-dev-certs.sh](scripts/gen-dev-certs.sh) generates a
test CA, server cert, and client cert (the same recipe used to verify every change to this server), plus a matching
`config.json`:

```bash
scripts/gen-dev-certs.sh ./.devcerts
docker run --rm -p 8443:8443 \
  -v "$(pwd)/.devcerts:/etc/estd:ro" \
  -v "$(pwd)/.devcerts/data:/var/lib/estd:rw" \
  ghcr.io/ffbarrie/est:develop

# from another terminal:
curl --cacert ./.devcerts/server.crt https://localhost:8443/.well-known/est/cacerts
```

## Architecture

See [AGENTS.md](AGENTS.md) for the package layout, extension points (`CABackend`, `Store`), and the conventions this
codebase follows — written for whoever (human or agent) works on this code next.
