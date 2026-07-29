// Package store persists certificate signing requests and issued
// certificates. This is a v1 placeholder abstraction: the file-based
// implementation here is expected to be swapped for something heavier
// later, so callers should depend only on the Store interface.
package store

import (
	"context"
	"crypto/x509"
	"math/big"
	"time"
)

// Metadata records context about a CSR or certificate beyond its raw DER.
type Metadata struct {
	// Requester is the authenticated mTLS client's Subject.CommonName, if
	// any (populated for /simpleenroll and /simplereenroll; empty for
	// unauthenticated bootstrap operations).
	Requester string

	RemoteAddr string
	ReceivedAt time.Time
}

// Store persists CSRs and issued certificates, keyed by certificate serial
// number.
type Store interface {
	PutCSR(ctx context.Context, serial *big.Int, csrDER []byte, meta Metadata) error
	PutCertificate(ctx context.Context, serial *big.Int, certDER []byte, meta Metadata) error
	GetCertificate(ctx context.Context, serial *big.Int) (*x509.Certificate, error)
}
