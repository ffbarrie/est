package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genSelfSignedCA creates a self-signed CA certificate and key pair for
// tests, using the given signer.
func genSelfSignedCA(t *testing.T, key crypto.Signer, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create self-signed CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert
}

func newTestLocalCA(t *testing.T) (*LocalCA, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caCert := genSelfSignedCA(t, caKey, "Test Local CA")
	return NewLocalCA(caCert, caKey, RandomSerialSource{}, 24*time.Hour), caCert
}

func genCSR(t *testing.T, tmpl *x509.CertificateRequest) (*x509.CertificateRequest, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr, key
}

func TestIssueCertificate_CopiesIdentity(t *testing.T) {
	localCA, _ := newTestLocalCA(t)

	csr, _ := genCSR(t, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "device01.example.test"},
		DNSNames:    []string{"device01.example.test"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
	})

	cert, err := localCA.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	if cert.Subject.CommonName != "device01.example.test" {
		t.Errorf("CommonName = %q, want device01.example.test", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "device01.example.test" {
		t.Errorf("DNSNames = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Errorf("IPAddresses = %v", cert.IPAddresses)
	}
}

func TestIssueCertificate_ServerControlledFields(t *testing.T) {
	localCA, caCert := newTestLocalCA(t)

	csr, _ := genCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device02.example.test"}})

	cert, err := localCA.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	if cert.IsCA {
		t.Error("issued certificate has IsCA=true, want false")
	}
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid = false, want true")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want DigitalSignature (ECDSA CSR key)", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if string(cert.AuthorityKeyId) != string(caCert.SubjectKeyId) {
		t.Errorf("AuthorityKeyId = %x, want %x", cert.AuthorityKeyId, caCert.SubjectKeyId)
	}
	wantSKID, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		t.Fatalf("subjectKeyID: %v", err)
	}
	if string(cert.SubjectKeyId) != string(wantSKID) {
		t.Errorf("SubjectKeyId = %x, want %x", cert.SubjectKeyId, wantSKID)
	}
}

func TestIssueCertificate_RSAKeyUsage(t *testing.T) {
	localCA, _ := newTestLocalCA(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-device.example.test"},
	}, rsaKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	cert, err := localCA.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v (RSA CSR key)", cert.KeyUsage, want)
	}
}

func TestIssueCertificate_RejectsBadSignature(t *testing.T) {
	localCA, _ := newTestLocalCA(t)

	csr, _ := genCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "tampered.example.test"}})

	// Corrupt the raw DER's final byte, which lands in the CSR's signature,
	// to invalidate the self-signature without touching its structure.
	tampered := append([]byte(nil), csr.Raw...)
	tampered[len(tampered)-1] ^= 0xFF
	badCSR, err := x509.ParseCertificateRequest(tampered)
	if err != nil {
		t.Fatalf("parse tampered CSR: %v", err)
	}

	_, err = localCA.IssueCertificate(context.Background(), badCSR)
	if err != ErrInvalidCSRSignature {
		t.Errorf("IssueCertificate error = %v, want ErrInvalidCSRSignature", err)
	}
}

func TestIssueCertificate_IgnoresRequestedCAExtension(t *testing.T) {
	localCA, _ := newTestLocalCA(t)

	// Encode a basicConstraints extension requesting CA:true, and smuggle
	// it into the CSR via ExtraExtensions (the extensionRequest attribute).
	bc, err := asn1.Marshal(struct {
		IsCA bool
	}{IsCA: true})
	if err != nil {
		t.Fatalf("marshal basicConstraints: %v", err)
	}

	csr, _ := genCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "malicious.example.test"},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc},
		},
	})

	cert, err := localCA.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if cert.IsCA {
		t.Error("issued certificate honored the CSR's requested CA:true extension")
	}
}

func TestRandomSerialSource_Unique(t *testing.T) {
	src := RandomSerialSource{}
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := src.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if s.Sign() < 0 {
			t.Fatalf("serial %d is negative: %v", i, s)
		}
		key := s.String()
		if seen[key] {
			t.Fatalf("duplicate serial generated: %v", s)
		}
		seen[key] = true
	}
}

func TestLoadCAKeyPair(t *testing.T) {
	dir := t.TempDir()

	t.Run("ECDSA SEC1 and PKCS8", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		cert := genSelfSignedCA(t, key, "ECDSA CA")

		certPath := filepath.Join(dir, "ec-ca.crt")
		writePEM(t, certPath, "CERTIFICATE", cert.Raw)

		for _, variant := range []struct {
			name    string
			marshal func() ([]byte, string)
		}{
			{"sec1", func() ([]byte, string) {
				der, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					t.Fatalf("marshal SEC1: %v", err)
				}
				return der, "EC PRIVATE KEY"
			}},
			{"pkcs8", func() ([]byte, string) {
				der, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatalf("marshal PKCS8: %v", err)
				}
				return der, "PRIVATE KEY"
			}},
		} {
			t.Run(variant.name, func(t *testing.T) {
				der, blockType := variant.marshal()
				keyPath := filepath.Join(dir, "ec-ca-"+variant.name+".key")
				writePEM(t, keyPath, blockType, der)

				gotCert, gotKey, err := LoadCAKeyPair(certPath, keyPath)
				if err != nil {
					t.Fatalf("LoadCAKeyPair: %v", err)
				}
				if gotCert.Subject.CommonName != "ECDSA CA" {
					t.Errorf("CommonName = %q", gotCert.Subject.CommonName)
				}
				if _, ok := gotKey.Public().(*ecdsa.PublicKey); !ok {
					t.Errorf("loaded key public type = %T, want *ecdsa.PublicKey", gotKey.Public())
				}
			})
		}
	})

	t.Run("RSA PKCS1", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		cert := genSelfSignedCA(t, key, "RSA CA")

		certPath := filepath.Join(dir, "rsa-ca.crt")
		writePEM(t, certPath, "CERTIFICATE", cert.Raw)

		keyPath := filepath.Join(dir, "rsa-ca.key")
		writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))

		gotCert, gotKey, err := LoadCAKeyPair(certPath, keyPath)
		if err != nil {
			t.Fatalf("LoadCAKeyPair: %v", err)
		}
		if gotCert.Subject.CommonName != "RSA CA" {
			t.Errorf("CommonName = %q", gotCert.Subject.CommonName)
		}
		if _, ok := gotKey.Public().(*rsa.PublicKey); !ok {
			t.Errorf("loaded key public type = %T, want *rsa.PublicKey", gotKey.Public())
		}
	})
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode PEM to %s: %v", path, err)
	}
}
