package openssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func opensslBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available, skipping")
	}
	return path
}

func runOpenSSL(t *testing.T, bin string, args ...string) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
}

// newTestCA sets up a scratch OpenSSL CA directory (index.txt/serial/
// newcerts/ + an openssl.cnf using the copy_extensions=copy plus fixed
// est_extensions shape verified during planning: a CSR-requested
// BasicConstraints/KeyUsage/ExtKeyUsage never overrides the fixed
// section, while a requested SAN still gets copied through) and returns
// a CA backend wired to it.
func newTestCA(t *testing.T) *CA {
	t.Helper()
	bin := opensslBinary(t)
	dir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dir, "newcerts"), 0o750); err != nil {
		t.Fatalf("mkdir newcerts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o640); err != nil {
		t.Fatalf("create index.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.txt.attr"), []byte("unique_subject = no\n"), 0o640); err != nil {
		t.Fatalf("create index.txt.attr: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "serial"), []byte("1000\n"), 0o640); err != nil {
		t.Fatalf("create serial: %v", err)
	}

	caKeyPath := filepath.Join(dir, "ca.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	runOpenSSL(t, bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", caKeyPath, "-out", caCertPath,
		"-days", "3650", "-subj", "/CN=Test OpenSSL Root CA")

	cnfPath := filepath.Join(dir, "openssl.cnf")
	cnf := fmt.Sprintf(`[ca]
default_ca = est_ca

[est_ca]
dir             = %[1]s
database        = %[1]s/index.txt
serial          = %[1]s/serial
new_certs_dir   = %[1]s/newcerts
certificate     = %[1]s/ca.crt
private_key     = %[1]s/ca.key
default_md      = sha256
default_days    = 365
policy          = est_policy
copy_extensions = copy
x509_extensions = est_extensions

[est_policy]
commonName = supplied

[est_extensions]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
`, dir)
	if err := os.WriteFile(cnfPath, []byte(cnf), 0o640); err != nil {
		t.Fatalf("write openssl.cnf: %v", err)
	}

	caCert, err := LoadCACertificate(caCertPath)
	if err != nil {
		t.Fatalf("LoadCACertificate: %v", err)
	}

	return NewCA(bin, cnfPath, caCert, "est_extensions")
}

func genCSR(t *testing.T, tmpl *x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

func TestCACertificates(t *testing.T) {
	c := newTestCA(t)
	certs, err := c.CACertificates(context.Background())
	if err != nil {
		t.Fatalf("CACertificates: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "Test OpenSSL Root CA" {
		t.Fatalf("certs = %v", certs)
	}
}

func TestIssueCertificate_HappyPath(t *testing.T) {
	c := newTestCA(t)
	csr := genCSR(t, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "device01.example.test"},
		DNSNames:    []string{"device01.example.test"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
	})

	cert, err := c.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	if cert.Subject.CommonName != "device01.example.test" {
		t.Errorf("CommonName = %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "device01.example.test" {
		t.Errorf("DNSNames = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Errorf("IPAddresses = %v", cert.IPAddresses)
	}
	if cert.IsCA {
		t.Error("issued certificate has IsCA=true, want false")
	}
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid = false, want true")
	}
	wantKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if cert.KeyUsage != wantKU {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, wantKU)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
}

// TestIssueCertificate_IgnoresRequestedCAExtension is the Go-side half of
// the adversarial case verified by hand during planning: a CSR that
// requests both a SAN and (via a smuggled raw extension) CA:TRUE must be
// issued with CA:FALSE regardless, while the SAN still comes through.
func TestIssueCertificate_IgnoresRequestedCAExtension(t *testing.T) {
	c := newTestCA(t)

	maliciousBasicConstraints, err := asn1.Marshal(struct{ IsCA bool }{IsCA: true})
	if err != nil {
		t.Fatalf("marshal basicConstraints: %v", err)
	}

	csr := genCSR(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "malicious.example.test"},
		DNSNames: []string{"malicious.example.test"},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: maliciousBasicConstraints},
		},
	})

	cert, err := c.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if cert.IsCA {
		t.Error("issued certificate honored the CSR's requested CA:TRUE extension")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "malicious.example.test" {
		t.Errorf("DNSNames = %v, want the requested SAN to still be copied through", cert.DNSNames)
	}
}

// TestIssueCertificate_ShellMetacharactersInSubject confirms the CSR only
// ever reaches openssl via a temp file path argument, never interpolated
// into a shell string: a Subject containing shell metacharacters must be
// issued normally, not executed.
func TestIssueCertificate_ShellMetacharactersInSubject(t *testing.T) {
	c := newTestCA(t)
	const dangerous = `$(touch /tmp/pwned)` + "`touch /tmp/pwned2`" + `;rm -rf /;'"`

	csr := genCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: dangerous},
	})

	cert, err := c.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if cert.Subject.CommonName != dangerous {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, dangerous)
	}
	if _, err := os.Stat("/tmp/pwned"); err == nil {
		t.Fatal("shell metacharacters in Subject were executed")
	}
}

func TestIssueCertificate_RejectsBadSignature(t *testing.T) {
	c := newTestCA(t)
	csr := genCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "tampered.example.test"}})

	tampered := append([]byte(nil), csr.Raw...)
	tampered[len(tampered)-1] ^= 0xFF
	badCSR, err := x509.ParseCertificateRequest(tampered)
	if err != nil {
		t.Fatalf("parse tampered CSR: %v", err)
	}

	_, err = c.IssueCertificate(context.Background(), badCSR)
	if err == nil {
		t.Fatal("IssueCertificate: expected error for bad signature, got nil")
	}
}

func TestIssueCertificate_Concurrent(t *testing.T) {
	c := newTestCA(t)

	const n = 5
	var wg sync.WaitGroup
	serials := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			csr := genCSR(t, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: fmt.Sprintf("concurrent-%d.example.test", i)},
			})
			cert, err := c.IssueCertificate(context.Background(), csr)
			if err != nil {
				errs[i] = err
				return
			}
			serials[i] = cert.SerialNumber.String()
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: IssueCertificate: %v", i, err)
		}
		if seen[serials[i]] {
			t.Fatalf("duplicate serial %s issued concurrently", serials[i])
		}
		seen[serials[i]] = true
	}
}

func TestLoadCACertificate_Errors(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadCACertificate(filepath.Join(dir, "does-not-exist.crt")); err == nil {
		t.Error("LoadCACertificate: expected error for missing file, got nil")
	}

	garbagePath := filepath.Join(dir, "garbage.crt")
	if err := os.WriteFile(garbagePath, []byte("not a PEM file"), 0o600); err != nil {
		t.Fatalf("write garbage file: %v", err)
	}
	if _, err := LoadCACertificate(garbagePath); err == nil {
		t.Error("LoadCACertificate: expected error for non-PEM content, got nil")
	}
}
