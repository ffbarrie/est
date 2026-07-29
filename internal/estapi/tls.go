package estapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// BuildTLSConfig constructs the server's TLS configuration. ClientAuth is
// set to VerifyClientCertIfGiven rather than RequireAndVerifyClientCert:
// tls.Config is per-listener, not per-route, and GET /cacerts exists
// precisely so a client with no certificate yet can bootstrap trust.
// VerifyClientCertIfGiven still verifies the chain whenever a certificate
// is presented — the handshake fails on an untrusted client cert, the same
// security bar as requiring one — it just doesn't force a cert to exist.
// handleSimpleEnroll and handleSimpleReenroll separately require a
// verified peer certificate and return 401 otherwise.
func BuildTLSConfig(serverCertFile, serverKeyFile string, clientCAFiles []string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("estapi: load server key pair: %w", err)
	}

	pool := x509.NewCertPool()
	for _, f := range clientCAFiles {
		pemBytes, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("estapi: read client CA file %s: %w", f, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("estapi: no certificates found in %s", f)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
