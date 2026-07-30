# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

An EST (RFC 7030 — Enrollment over Secure Transport) server, written in Go. It issues
and renews X.509 certificates over mTLS. The CA backend is pluggable, selected at
runtime via `ca_backend` in config: a local, `crypto/x509`-based backend (default), an
`openssl`-backed one that shells out to a real `openssl ca` command-line CA, or an
`ejbca`-backed one that calls EJBCA's REST API over HTTPS. All three backends
envisioned from the project's first design conversation now exist.

## Build, test, run

```bash
go build ./...              # build everything
go test ./...                # run all unit tests
go test ./... -race          # required for internal/store changes (concurrent writes)
gofmt -l .                   # must report nothing before committing
go vet ./...
```

There is no `Makefile` — the above are the actual commands, run directly.

Manual end-to-end verification (mTLS, real certs) requires generating a test CA,
server cert, and client cert with `openssl`, then exercising `/cacerts`,
`/simpleenroll`, and `/simplereenroll` with `curl --cert/--key/--cacert`. See git
history / PR description for the exact recipe if you need to redo this by hand.

## Layout

```
cmd/estd/main.go        entrypoint: config load, wiring, TLS listener, graceful shutdown
internal/ca/            CABackend interface + LocalCA (crypto/x509-based signer)
internal/ca/openssl/    CABackend impl that shells out to `openssl ca` (see below)
internal/ca/ejbca/      CABackend impl calling EJBCA's REST API over HTTPS (see below)
internal/pkcs7/         degenerate PKCS#7 SignedData encode/decode (cryptobyte)
internal/csrattrs/      CsrAttrs response encoder for /csrattrs (cryptobyte)
internal/store/         Store interface + FileStore (CSR/cert persistence)
internal/estapi/        HTTP handlers, TLS/mTLS config, routing
internal/config/        JSON config loading + validation
```

## Conventions and constraints (don't relitigate these without asking)

- **`LocalCA` never shells out; `internal/ca/openssl` deliberately does, and only
  there.** `internal/pkcs7` and `internal/csrattrs` use `openssl` solely as a
  *test-time oracle* (see `internal/pkcs7/pkcs7_test.go`), never invoked by the
  server itself. `internal/ca/openssl` is the one exception, by design: it's a
  `ca_backend: "openssl"`-selected `CABackend` that signs by invoking a real
  `openssl ca` subprocess against an operator's CA directory. If you touch that
  package, preserve its two load-bearing safety properties (both have tests): CSR
  content only ever reaches `openssl` via a temp file path argument, never a CLI
  argument or shell string (no command-injection surface); and issued certificates
  are checked for `IsCA` after the fact as a defense-in-depth backstop against a
  misconfigured operator `openssl.cnf` (see `openssl-ca.example.cnf` for the
  `copy_extensions = copy` + fixed `[est_extensions]` section shape this depends on).
- **`CABackend` and `Store` are the extension seams.** `internal/ca/openssl` and
  `internal/ca/ejbca` are both real precedents for "a CA backend becomes a sibling
  package under `internal/ca/` implementing the same interface" — a fourth is just as
  easy to add the same way. A different storage backend would replace
  `internal/store`'s `FileStore` without touching `internal/ca` or `internal/estapi`.
  Don't hard-code assumptions that only one implementation of either will ever exist.
- **`internal/ca/ejbca`'s mTLS-to-EJBCA design has been tried against a real EJBCA
  instance (EJBCA 9.3.7 Community, `keyfactor/ejbca-ce`) and failed at the TLS
  connector level** — not just tested against the mock server shaped like EJBCA's
  published OpenAPI spec. With Protocol Configuration, CA trust, and administrator
  role/access-rule bindings all independently confirmed correct (verified via the
  instance's own audit log), every REST endpoint tested returns a clean response
  with no client certificate presented, and the connection is reset immediately
  after a fully successful TLS handshake as soon as *any* client certificate is
  presented — reproduced with two different client certificates from two different
  issuing CAs sharing one key, with two different TLS stacks (curl/LibreSSL and
  `openssl s_client`/OpenSSL), with zero corresponding entry in EJBCA's own audit
  log (meaning the request never reaches the EJBCA application layer at all). This
  points at a broken or unsupported two-way-TLS connector configuration in that
  container image, not at anything fixable via `internal/ca/ejbca`'s code or
  config. It is consistent with a separate, independent finding recorded outside
  this repo (a sibling project's ADR, working against the same EJBCA instance):
  that project deliberately avoided client-certificate auth for EJBCA enrollment on
  Community Edition, using CMP HMAC auth instead. If you touch this package, do not
  claim it's been verified end-to-end against a real instance — only that the
  mTLS-auth design was attempted and hit an infrastructure-level wall, distinct from
  `internal/ca/openssl`, which *is* verified against the real `openssl` binary. It
  also generates a random one-time username/password per enrollment — documented as
  an assumption about the operator's EJBCA End Entity Profile allowing ad hoc
  credentials, not a universal guarantee.
- **Certificate template fields that affect trust are always server-controlled,
  never taken from the CSR**: `BasicConstraints`/`IsCA`, `KeyUsage`, `ExtKeyUsage`.
  A client-supplied CSR must never be able to request `CA:true` or arbitrary EKUs.
  See `internal/ca/local.go` and the corresponding test in `internal/ca/ca_test.go`
  (`TestIssueCertificate_IgnoresRequestedCAExtension`).
- **v1 auth is mTLS-only**, for both `/simpleenroll` and `/simplereenroll` — no
  HTTP Basic/Digest fallback. `/cacerts` is reachable without a client cert
  (bootstrap use case); the TLS layer uses `tls.VerifyClientCertIfGiven` rather
  than `RequireAndVerifyClientCert` for this reason (see `internal/estapi/tls.go`).
- **`/simplereenroll` identity check is intentionally simple** (`internal/estapi/identity.go`):
  exact CommonName match plus an identical SAN set between the CSR and the
  authenticated client certificate. Not a general policy engine — mismatches are
  rejected outright (403), not partially honored.
- **Avoid third-party dependencies where the stdlib covers it.** The one exception is
  `golang.org/x/crypto/cryptobyte` (used in `internal/pkcs7` and `internal/csrattrs`
  to build/parse ASN.1 instead of hand-rolled `encoding/asn1.RawValue` tag/length
  arithmetic) — Go-team-maintained infrastructure purpose-built for exactly this,
  and what `crypto/x509` itself uses internally. This is a narrow, deliberate
  exception, not a general relaxation of the no-dependencies stance. If a task
  seems to need a different third-party dependency, flag it rather than adding it
  silently.
- **`/fullcmc` and `/serverkeygen` are out of scope for v1** — not routed, 404 by
  default. Fine to add later behind the existing interfaces if asked. (`/csrattrs`
  *is* implemented — see `internal/csrattrs`.)

## Git flow

Branch flow is `feature/* -> develop -> main`. Branch new work off `develop`, not
`main`. `.metadata/` (Eclipse workspace state) and `.claude/settings.local.json`
are gitignored on purpose — don't re-add them without checking first.
