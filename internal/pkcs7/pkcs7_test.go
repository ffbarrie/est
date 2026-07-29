package pkcs7

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func genCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		certs []*x509.Certificate
	}{
		{"empty", nil},
		{"single", []*x509.Certificate{genCert(t, "single", 1)}},
		{"multi", []*x509.Certificate{genCert(t, "one", 1), genCert(t, "two", 2), genCert(t, "three", 3)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := EncodeCertsOnly(tc.certs)
			if err != nil {
				t.Fatalf("EncodeCertsOnly: %v", err)
			}

			got, err := DecodeCertsOnly(der)
			if err != nil {
				t.Fatalf("DecodeCertsOnly: %v", err)
			}

			if len(got) != len(tc.certs) {
				t.Fatalf("got %d certs, want %d", len(got), len(tc.certs))
			}
			for i, c := range got {
				if !bytes.Equal(c.Raw, tc.certs[i].Raw) {
					t.Errorf("cert %d: raw DER mismatch", i)
				}
			}
		})
	}
}

func TestDecodeCertsOnly_Malformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x30, 0x03, 0x02, 0x01, 0x01}, // valid ASN.1 SEQUENCE, wrong shape entirely
		[]byte("not asn.1 at all"),
	}
	for i, der := range cases {
		if _, err := DecodeCertsOnly(der); err == nil {
			t.Errorf("case %d: expected error decoding malformed input, got nil", i)
		}
	}
}

// TestEncodeCertsOnly_OpenSSLGolden compares our DER output against
// `openssl crl2pkcs7 -nocrl`, using openssl purely as a test-time oracle
// (never invoked at runtime by the server itself).
func TestEncodeCertsOnly_OpenSSLGolden(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available, skipping golden test")
	}

	certs := []*x509.Certificate{genCert(t, "golden-one", 101), genCert(t, "golden-two", 102)}

	var pemBundle bytes.Buffer
	for _, c := range certs {
		if err := pem.Encode(&pemBundle, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatalf("pem encode: %v", err)
		}
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(bundlePath, pemBundle.Bytes(), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	cmd := exec.Command(opensslPath, "crl2pkcs7", "-nocrl", "-certfile", bundlePath, "-outform", "DER")
	wantDER, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl crl2pkcs7: %v", err)
	}

	gotDER, err := EncodeCertsOnly(certs)
	if err != nil {
		t.Fatalf("EncodeCertsOnly: %v", err)
	}

	if !bytes.Equal(gotDER, wantDER) {
		t.Errorf("DER mismatch with openssl oracle:\n got  %x\n want %x", gotDER, wantDER)
	}
}
