# est

An [EST](https://www.rfc-editor.org/rfc/rfc7030) (Enrollment over Secure Transport) server, written in Go. It issues
and renews X.509 certificates over mutual TLS. The CA backend is pluggable behind a small interface, selected at
runtime by one config field (`ca_backend`) — no rebuild required to switch. Three implementations exist today: a
local, in-process CA built on `crypto/x509`; one that shells out to a real `openssl ca`; and one that calls EJBCA's
REST API. See [CA backends](#ca-backends) below.

## Status

- **Endpoints implemented:** `GET /cacerts`, `POST /simpleenroll`, `POST /simplereenroll`, `GET /csrattrs`.
- **Not implemented:** `/fullcmc`, `/serverkeygen` (no concrete need for them yet; both interfaces are small enough
  to extend without a redesign).
- **Auth:** mutual TLS only, for every endpoint. `/cacerts` and `/csrattrs` accept an anonymous connection (no client
  certificate) per RFC 7030 — that's their bootstrap use case. `/simpleenroll` and `/simplereenroll` require a client
  certificate the server already trusts.
- **CA backend:** pluggable via `ca_backend` in config — `"local"` (`crypto/x509`-based, default), `"openssl"`
  (shells out to `openssl ca`), or `"ejbca"` (EJBCA's REST API). See [CA backends](#ca-backends) below; a fourth
  implementation would be just as easy to add behind the same `ca.CABackend` interface, with no HTTP-layer changes.
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

One external dependency (`golang.org/x/crypto`, for ASN.1 construction) — a narrow, deliberate exception to an
otherwise stdlib-only codebase, not an oversight; see `AGENTS.md`.

## Running it

```bash
go build -o estd ./cmd/estd
./estd -config config.json
```

`config.json` is a JSON file. Three fully worked examples exist, one per CA backend — copy whichever matches, then
edit the paths: [config.example.json](config.example.json) (`"local"`, the default),
[config-openssl.example.json](config-openssl.example.json), [config-ejbca.example.json](config-ejbca.example.json).
They share every field *except* the CA-backend-related ones (`ca_backend` and whichever of `ca_key_file`/
`openssl_ca`/`ejbca_ca` that backend needs) — see the
field reference below.

### Config fields

| Field | Required | Meaning |
|---|---|---|
| `listen_addr` | yes | Address to listen on, e.g. `"0.0.0.0:8443"` |
| `server_cert_file` / `server_key_file` | yes | The server's own TLS certificate/key (PEM) |
| `client_ca_files` | yes | PEM bundle(s) of CA certificates trusted for client mTLS |
| `ca_backend` | no | `"local"` (default), `"openssl"`, or `"ejbca"` — which `CABackend` signs certificates; see below |
| `ca_cert_file` | only for `ca_backend: "local"`/`"openssl"` | The issuing CA's certificate (PEM). Not read under `"ejbca"`, which fetches it live |
| `ca_key_file` | only for `ca_backend: "local"` | The issuing CA's private key (PEM). Not read under `"openssl"`/`"ejbca"` |
| `openssl_ca` | only for `ca_backend: "openssl"` | `{config_file, openssl_path, extensions_section}` — see below |
| `ejbca_ca` | only for `ca_backend: "ejbca"` | `{base_url, client_cert_file, client_key_file, ca_name, ca_subject_dn, certificate_profile_name, end_entity_profile_name, server_ca_file?}` — see below |
| `store_dir` | yes | Directory where issued certificates and CSRs are persisted |
| `cert_validity` | yes | Validity duration given to every issued certificate, e.g. `"8760h"` |
| `csr_attrs` | no | Configures the `GET /csrattrs` response; omit entirely for a `204` response |

### CA backends

Three `ca.CABackend` implementations exist, selected by `ca_backend`. They differ in where the CA certificate and
private key live: `"local"` is fully offline (both in this process), `"openssl"` is local-file-plus-subprocess (CA
cert read locally, key never leaves the `openssl` subprocess), `"ejbca"` is fully remote (both fetched from EJBCA
over HTTPS, nothing CA-related stored locally at all).

- **`"local"`** (default) — signs in-process via `crypto/x509`, no external process. `ca_key_file` is required in
  this mode; the server process holds the CA private key in memory. See
  [config.example.json](config.example.json) for a full example.
- **`"openssl"`** — signs by shelling out to a real `openssl ca` command against an operator-provisioned OpenSSL CA
  directory (the classic `index.txt`/`serial`/`newcerts/` flat-file database). The server process **never reads or
  holds the CA private key** in this mode — key access is delegated entirely to the `openssl` subprocess, whose own
  `openssl.cnf` points at it. See [config-openssl.example.json](config-openssl.example.json) for a full example;
  the backend-specific part is:
  ```json
  "ca_backend": "openssl",
  "openssl_ca": {
    "config_file": "/etc/estd/openssl-ca/openssl.cnf"
  }
  ```
  See [openssl-ca.example.cnf](openssl-ca.example.cnf) for a fully worked, tested `openssl.cnf` — including the
  `copy_extensions = copy` + fixed `[est_extensions]` section combination that keeps `BasicConstraints`/`KeyUsage`/
  `ExtKeyUsage` server-controlled (never CSR-derived) while still copying a requested SAN through, the same
  guarantee `LocalCA` provides in Go code. `scripts/gen-dev-certs.sh` also generates a throwaway OpenSSL CA
  directory (`openssl-ca/` + a runtime `config-openssl.json`, distinct from the committed
  `config-openssl.example.json` above) alongside its usual dev certs, for trying this backend locally.

  **Not currently usable with the published Docker image**: the distroless base has no shell, package manager, or
  `openssl` binary at all (by design — see [Running via Docker](#running-via-docker)), so `ca_backend: "openssl"`
  will fail `config.Validate()`'s startup check inside that container. Use the `"local"` backend in Docker, or the
  `openssl` backend when running `estd` directly on a host that has `openssl` installed.
- **`"ejbca"`** — signs via [EJBCA's REST API](https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface) over
  HTTPS, authenticating to EJBCA with a TLS client certificate (the same mechanism EJBCA's own Admin GUI uses,
  mapped to an administrator role with enrollment privileges). Neither `ca_cert_file` nor `ca_key_file` is read in
  this mode — the CA certificate is fetched live from EJBCA too. See
  [config-ejbca.example.json](config-ejbca.example.json) for a full example; the backend-specific part is:
  ```json
  "ca_backend": "ejbca",
  "ejbca_ca": {
    "base_url": "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
    "client_cert_file": "/etc/estd/ejbca-client.crt",
    "client_key_file": "/etc/estd/ejbca-client.key",
    "ca_name": "ExampleCA",
    "ca_subject_dn": "CN=Example CA,O=Example Org,C=SE",
    "certificate_profile_name": "ENDUSER",
    "end_entity_profile_name": "ExampleEEP"
  }
  ```
  `client_cert_file`/`client_key_file` are **estd's own credentials for authenticating to EJBCA** — not something
  this repo can generate for you (unlike the other two backends' dev-cert tooling): obtain them from whoever
  administers your EJBCA instance, issued with an administrator role authorized to enroll against the configured
  CA/profiles. Similarly, `client_ca_files` (the trust anchor for *incoming* EST client mTLS) has no local CA file
  to reuse under this backend, unlike `"local"`/`"openssl"` — it's a separate, operator-provided bundle, since
  there's no reason it need be the same CA EJBCA issues from.

  Each enrollment generates a random, one-time username/password to satisfy EJBCA's end-entity model — **this
  assumes the configured End Entity Profile permits ad hoc/self-service enrollment with arbitrary credentials**,
  which is not universal across EJBCA deployments; check this against your own profile configuration.

  **Verification caveat, stated plainly**: this backend's mTLS-to-EJBCA design was tried against a real EJBCA
  instance (EJBCA 9.3.7 Community, `keyfactor/ejbca-ce`) and did not work — not just tested against a mock server
  shaped like EJBCA's published OpenAPI spec. With Protocol Configuration, CA trust, and the administrator role's
  access rules all independently confirmed correct on that instance (verified via its own audit log), every REST
  endpoint tried returned a normal response with no client certificate presented, but reset the connection
  immediately after a fully successful TLS handshake as soon as *any* client certificate was presented — reproduced
  across two client certificates from two different issuing CAs sharing one key, and across two different TLS
  stacks (curl/LibreSSL and `openssl s_client`/OpenSSL), with no corresponding entry at all in EJBCA's own audit
  log (the request never reached the application layer). That points to a broken or unsupported two-way-TLS
  connector configuration in that specific container image, not to a bug in this backend's request logic. Treat
  the mock-verified request/response handling as a correct, spec-conformant starting point, but validate the
  mTLS-authentication path itself against your own deployment before relying on it — it may need an EJBCA
  Enterprise instance, a differently configured connector, or (as one other project independently found against
  the same EJBCA Community instance) an entirely different auth mechanism such as CMP with HMAC.

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
