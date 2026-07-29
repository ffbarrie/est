// Package openssl implements ca.CABackend by driving a real `openssl ca`
// command-line CA — the classic index.txt/serial/newcerts flat-file
// database — as the backing store for issued certificates. Unlike
// ca.LocalCA, this process never holds the CA private key itself: key
// access is delegated entirely to the openssl subprocess, whose own
// openssl.cnf points at the key.
package openssl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/ffbarrie/est/internal/ca"
)

// CA is a ca.CABackend that signs certificates by invoking `openssl ca`
// against an operator-provisioned OpenSSL CA directory (index.txt,
// serial, newcerts/, and an openssl.cnf describing them — see
// openssl-ca.example.cnf at the repo root for the required shape,
// particularly copy_extensions = copy plus a fixed x509_extensions
// section: that combination is what keeps BasicConstraints/KeyUsage/
// ExtKeyUsage server-controlled while still letting the CSR's requested
// SAN through, mirroring LocalCA's equivalent guarantee).
type CA struct {
	opensslPath       string
	configFile        string
	caCert            *x509.Certificate
	extensionsSection string

	// mu serializes `openssl ca` invocations from this process against the
	// shared index.txt/serial state. This does not protect against another
	// process touching the same CA directory concurrently — the same
	// single-process assumption internal/store's FileStore already makes.
	mu sync.Mutex
}

// NewCA constructs a CA. opensslPath is the path to the openssl binary
// (callers typically resolve it once via exec.LookPath at startup, so a
// missing binary fails fast rather than on first enrollment); configFile
// is the operator's openssl.cnf; extensionsSection names the -extensions
// section within it that fixes BasicConstraints/KeyUsage/ExtKeyUsage.
func NewCA(opensslPath, configFile string, caCert *x509.Certificate, extensionsSection string) *CA {
	return &CA{
		opensslPath:       opensslPath,
		configFile:        configFile,
		caCert:            caCert,
		extensionsSection: extensionsSection,
	}
}

// LoadCACertificate reads and parses a CA certificate from a PEM file.
// Unlike ca.LoadCAKeyPair, this never touches a private key — the whole
// point of this backend is that estd never holds one.
func LoadCACertificate(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("openssl: read CA certificate: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("openssl: no PEM block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("openssl: parse CA certificate: %w", err)
	}
	return cert, nil
}

// CACertificates implements ca.CABackend.
func (c *CA) CACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{c.caCert}, nil
}

// IssueCertificate implements ca.CABackend by shelling out to `openssl
// ca`. The CSR is exchanged via temp files, never as a CLI argument or
// through a shell, so CSR content (including an adversarial Subject
// containing shell metacharacters) can never reach a shell interpreter.
func (c *CA) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, ca.ErrInvalidCSRSignature
	}

	csrFile, err := os.CreateTemp("", "estd-csr-*.pem")
	if err != nil {
		return nil, fmt.Errorf("openssl: create temp CSR file: %w", err)
	}
	defer os.Remove(csrFile.Name())
	writeErr := pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	closeErr := csrFile.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("openssl: write temp CSR file: %w", writeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("openssl: close temp CSR file: %w", closeErr)
	}

	certOut, err := os.CreateTemp("", "estd-cert-*.pem")
	if err != nil {
		return nil, fmt.Errorf("openssl: create temp cert file: %w", err)
	}
	certPath := certOut.Name()
	certOut.Close()
	defer os.Remove(certPath)

	if err := c.runOpenSSLCA(ctx, csrFile.Name(), certPath); err != nil {
		return nil, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("openssl: read issued certificate: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("openssl: no PEM block in openssl ca output")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("openssl: parse issued certificate: %w", err)
	}

	// Defense-in-depth: never hand back a CA certificate, even if the
	// operator's openssl.cnf is misconfigured. LocalCA enforces this in
	// the template it builds in Go; here we can only check the result.
	if cert.IsCA {
		return nil, fmt.Errorf("openssl: issued certificate has CA:TRUE; check the %q extensions section in %s", c.extensionsSection, c.configFile)
	}

	return cert, nil
}

func (c *CA) runOpenSSLCA(ctx context.Context, csrPath, certPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := exec.CommandContext(ctx, c.opensslPath, "ca",
		"-batch",
		"-config", c.configFile,
		"-in", csrPath,
		"-out", certPath,
		"-notext",
		"-extensions", c.extensionsSection,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openssl: openssl ca failed: %w: %s", err, string(output))
	}
	return nil
}

var _ ca.CABackend = (*CA)(nil)
