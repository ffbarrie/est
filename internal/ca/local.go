package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// LocalCA is a CABackend that signs certificates in-process using a CA
// certificate and private key loaded from disk, via crypto/x509.
type LocalCA struct {
	cert     *x509.Certificate
	key      crypto.Signer
	serials  SerialSource
	validity time.Duration

	// ExtKeyUsage is applied to every certificate this CA issues. It is
	// never taken from the CSR. Defaults to ExtKeyUsageClientAuth, the
	// primary use case for mTLS-authenticated EST clients.
	ExtKeyUsage []x509.ExtKeyUsage

	// NotBeforeSkew backdates issued certificates' NotBefore to tolerate
	// clock drift between the CA and the relying party. Defaults to 5
	// minutes when zero.
	NotBeforeSkew time.Duration
}

// NewLocalCA constructs a LocalCA. cert and key are the CA's own
// certificate and private key; validity is the lifetime given to every
// certificate this CA issues.
func NewLocalCA(cert *x509.Certificate, key crypto.Signer, serials SerialSource, validity time.Duration) *LocalCA {
	return &LocalCA{
		cert:        cert,
		key:         key,
		serials:     serials,
		validity:    validity,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// LoadCAKeyPair reads a CA certificate and private key from PEM files.
// The key may be encoded as PKCS#8, PKCS#1 (RSA) or SEC1 (EC) — the
// formats produced by `openssl genpkey`/`genrsa`/`ecparam -genkey`.
func LoadCAKeyPair(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: read CA certificate: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("ca: no PEM block found in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("ca: no PEM block found in %s", keyPath)
	}

	signer, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse CA key: %w", err)
	}

	return cert, signer, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key of type %T does not implement crypto.Signer", key)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unrecognized private key format (tried PKCS#8, PKCS#1, SEC1 EC)")
}

// CACertificates implements CABackend.
func (l *LocalCA) CACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{l.cert}, nil
}

// IssueCertificate implements CABackend. Subject and SAN fields are copied
// from the CSR; BasicConstraints, KeyUsage and ExtKeyUsage are always
// server-controlled and never taken from the CSR, since a client-supplied
// CSR must not be able to request CA:true or arbitrary extended key usages.
func (l *LocalCA) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, ErrInvalidCSRSignature
	}

	serial, err := l.serials.Next()
	if err != nil {
		return nil, fmt.Errorf("ca: allocate serial: %w", err)
	}

	skid, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ca: compute subject key id: %w", err)
	}

	skew := l.NotBeforeSkew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		NotBefore:             now.Add(-skew),
		NotAfter:              now.Add(l.validity),
		KeyUsage:              keyUsageFor(csr.PublicKeyAlgorithm),
		ExtKeyUsage:           l.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          skid,
		AuthorityKeyId:        l.cert.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, l.cert, csr.PublicKey, l.key)
	if err != nil {
		return nil, fmt.Errorf("ca: create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse issued certificate: %w", err)
	}
	return cert, nil
}

func keyUsageFor(alg x509.PublicKeyAlgorithm) x509.KeyUsage {
	switch alg {
	case x509.RSA:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	default:
		return x509.KeyUsageDigitalSignature
	}
}

// subjectKeyID computes an RFC 5280 §4.2.1.2 method (1) key identifier: the
// SHA-1 hash of the subjectPublicKey BIT STRING content, excluding its tag,
// length and unused-bits count.
func subjectKeyID(pub any) ([]byte, error) {
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.PublicKey.Bytes)
	return sum[:], nil
}
