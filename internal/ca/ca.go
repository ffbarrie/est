// Package ca defines the CA-backend abstraction used by the EST server and
// a local, crypto/x509-based implementation of it.
package ca

import (
	"context"
	"crypto/x509"
	"errors"
)

// CABackend issues certificates from CSRs and reports the CA's own
// certificate(s). Implementations may be a local, in-process CA or a
// remote CA such as EJBCA; the estapi layer depends only on this interface.
type CABackend interface {
	// CACertificates returns the certificate(s) to serve from GET /cacerts,
	// ordered issuing-CA-first.
	CACertificates(ctx context.Context) ([]*x509.Certificate, error)

	// IssueCertificate validates csr and, on success, signs and returns the
	// new certificate. It does not persist anything; callers are
	// responsible for storing the result via a separate store.Store.
	IssueCertificate(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error)
}

var (
	// ErrInvalidCSRSignature indicates the CSR's self-signature did not
	// verify against its own public key (proof-of-possession failure).
	ErrInvalidCSRSignature = errors.New("ca: csr signature does not verify")

	// ErrCABackendUnavailable indicates the backend could not service the
	// request for reasons unrelated to the CSR itself (e.g. a remote CA is
	// unreachable).
	ErrCABackendUnavailable = errors.New("ca: backend unavailable")
)
