# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

An EST (RFC 7030 — Enrollment over Secure Transport) server, written in Go. It issues
and renews X.509 certificates over mTLS. The CA backend is pluggable; v1 ships a
local, `crypto/x509`-based backend, with an EJBCA-backed implementation planned as a
second backend behind the same interface.

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
internal/pkcs7/         hand-rolled degenerate PKCS#7 SignedData encode/decode
internal/store/         Store interface + FileStore (CSR/cert persistence)
internal/estapi/        HTTP handlers, TLS/mTLS config, routing
internal/config/        JSON config loading + validation
```

## Conventions and constraints (don't relitigate these without asking)

- **No shelling out to `openssl` at runtime.** The CA backend signs certificates
  in-process via `crypto/x509`. `openssl` is used only as a *test-time oracle*
  (see `internal/pkcs7/pkcs7_test.go`) to cross-check our hand-rolled ASN.1 output —
  never invoked by the server itself.
- **`CABackend` and `Store` are the extension seams.** A second CA backend (e.g.
  EJBCA) becomes a sibling package under `internal/ca/` implementing the same
  interface; a different storage backend replaces `internal/store`'s `FileStore`
  without touching `internal/ca` or `internal/estapi`. Don't hard-code assumptions
  that only one implementation of either will ever exist.
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
- **Avoid third-party dependencies where the stdlib covers it.** `go.mod` currently
  has no external dependencies; this was a deliberate choice (see the PKCS#7
  encoder), not an oversight. If a task seems to need one, flag it rather than
  adding it silently.
- **`/fullcmc`, `/serverkeygen`, `/csrattrs` are out of scope for v1** — not routed,
  404 by default. Fine to add later behind the existing interfaces if asked.

## Git flow

Branch flow is `feature/* -> develop -> main`. Branch new work off `develop`, not
`main`. `.metadata/` (Eclipse workspace state) and `.claude/settings.local.json`
are gitignored on purpose — don't re-add them without checking first.
