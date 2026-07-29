package ejbca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ffbarrie/est/internal/ca"
)

func genTLSCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func genCert(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
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

func genCSR(t *testing.T, cn string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

// newMockServer starts an httptest.Server requiring some client
// certificate (not validated against a specific CA — sufficient to prove
// our client presents one at all) running handler.
func newMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// newTestCA builds a *CA directly (bypassing NewCA's file-loading) wired
// to ts, presenting a throwaway self-signed client certificate.
func newTestCA(t *testing.T, ts *httptest.Server) *CA {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())

	return &CA{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{genTLSCert(t, "estd-test-client")},
					RootCAs:      pool,
				},
			},
			Timeout: 10 * time.Second,
		},
		baseURL:                ts.URL,
		caName:                 "TestCA",
		caSubjectDN:            "CN=Test EJBCA Root CA",
		certificateProfileName: "ENDUSER",
		endEntityProfileName:   "ExampleEEP",
	}
}

func TestIssueCertificate_HappyPath(t *testing.T) {
	issuedCert := genCert(t, "device01.example.test", false)
	var capturedReq enrollRequest
	var sawClientCert bool

	ts := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			sawClientCert = true
		}
		if r.URL.Path != "/certificate/pkcs10enroll" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &capturedReq); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{ //nolint:errcheck
			Certificate: base64.StdEncoding.EncodeToString(issuedCert.Raw),
		})
	})

	c := newTestCA(t, ts)
	csr := genCSR(t, "device01.example.test")

	cert, err := c.IssueCertificate(context.Background(), csr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if cert.Subject.CommonName != "device01.example.test" {
		t.Errorf("CommonName = %q", cert.Subject.CommonName)
	}
	if !sawClientCert {
		t.Error("server did not see a client certificate — mTLS not presented")
	}
	if capturedReq.CertificateProfileName != "ENDUSER" {
		t.Errorf("CertificateProfileName = %q", capturedReq.CertificateProfileName)
	}
	if capturedReq.EndEntityProfileName != "ExampleEEP" {
		t.Errorf("EndEntityProfileName = %q", capturedReq.EndEntityProfileName)
	}
	if capturedReq.CertificateAuthorityName != "TestCA" {
		t.Errorf("CertificateAuthorityName = %q", capturedReq.CertificateAuthorityName)
	}
	if capturedReq.Username == "" || capturedReq.Password == "" {
		t.Error("expected non-empty generated username/password")
	}
	if !strings.Contains(capturedReq.CertificateRequest, "BEGIN CERTIFICATE REQUEST") {
		t.Errorf("certificate_request does not look like PEM: %q", capturedReq.CertificateRequest)
	}
	if capturedReq.ResponseFormat != "DER" {
		t.Errorf("ResponseFormat = %q, want DER", capturedReq.ResponseFormat)
	}
}

func TestIssueCertificate_ErrorResponse(t *testing.T) {
	ts := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"error_code":    400,
			"error_message": "CSR subject DN could not be parsed",
		})
	})

	c := newTestCA(t, ts)
	csr := genCSR(t, "device02.example.test")

	_, err := c.IssueCertificate(context.Background(), csr)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "CSR subject DN could not be parsed") {
		t.Errorf("error = %v, want it to mention EJBCA's error_message", err)
	}
}

func TestIssueCertificate_RejectsIssuedCACertificate(t *testing.T) {
	maliciousCert := genCert(t, "malicious.example.test", true) // IsCA=true

	ts := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{ //nolint:errcheck
			Certificate: base64.StdEncoding.EncodeToString(maliciousCert.Raw),
		})
	})

	c := newTestCA(t, ts)
	csr := genCSR(t, "malicious.example.test")

	if _, err := c.IssueCertificate(context.Background(), csr); err == nil {
		t.Fatal("expected error for a CA:TRUE issued certificate, got nil")
	}
}

func TestIssueCertificate_RejectsBadSignature(t *testing.T) {
	// baseURL deliberately unreachable: proves the signature check
	// short-circuits before any network call is attempted.
	c := &CA{
		client:      &http.Client{Timeout: time.Second},
		baseURL:     "https://127.0.0.1:1",
		caName:      "TestCA",
		caSubjectDN: "CN=Test EJBCA Root CA",
	}

	csr := genCSR(t, "tampered.example.test")
	tampered := append([]byte(nil), csr.Raw...)
	tampered[len(tampered)-1] ^= 0xFF
	badCSR, err := x509.ParseCertificateRequest(tampered)
	if err != nil {
		t.Fatalf("parse tampered CSR: %v", err)
	}

	_, err = c.IssueCertificate(context.Background(), badCSR)
	if !errors.Is(err, ca.ErrInvalidCSRSignature) {
		t.Errorf("error = %v, want ca.ErrInvalidCSRSignature", err)
	}
}

func TestCACertificates_SingleAndMultiCert(t *testing.T) {
	cases := []struct {
		name  string
		certs []*x509.Certificate
	}{
		{"single", []*x509.Certificate{genCert(t, "Test Root CA", true)}},
		{"chain", []*x509.Certificate{genCert(t, "Test Sub CA", true), genCert(t, "Test Root CA", true)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				// r.URL.Path is already URL-decoded by net/http; the wire
				// form (asserted implicitly by a successful round-trip
				// here) is what CACertificates builds via url.PathEscape.
				if r.URL.Path != "/ca/CN=Test EJBCA Root CA/certificate/download" {
					t.Fatalf("unexpected path: %s", r.URL.Path)
				}
				for _, cert := range tc.certs {
					pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}) //nolint:errcheck
				}
			})

			c := newTestCA(t, ts)
			got, err := c.CACertificates(context.Background())
			if err != nil {
				t.Fatalf("CACertificates: %v", err)
			}
			if len(got) != len(tc.certs) {
				t.Fatalf("got %d certs, want %d", len(got), len(tc.certs))
			}
			for i, cert := range got {
				if cert.Subject.CommonName != tc.certs[i].Subject.CommonName {
					t.Errorf("cert %d CommonName = %q, want %q", i, cert.Subject.CommonName, tc.certs[i].Subject.CommonName)
				}
			}
		})
	}
}

func TestCACertificates_HTTPError(t *testing.T) {
	ts := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"error_code":    404,
			"error_message": "CA does not exist",
		})
	})

	c := newTestCA(t, ts)
	if _, err := c.CACertificates(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	} else if !strings.Contains(err.Error(), "CA does not exist") {
		t.Errorf("error = %v, want it to mention EJBCA's error_message", err)
	}
}

func TestNewCA(t *testing.T) {
	dir := t.TempDir()
	clientCert := genTLSCert(t, "estd")

	writePEM := func(path, blockType string, der []byte) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
		defer f.Close()
		if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
			t.Fatalf("encode PEM to %s: %v", path, err)
		}
	}

	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	writePEM(certPath, "CERTIFICATE", clientCert.Certificate[0])

	keyDER, err := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	writePEM(keyPath, "PRIVATE KEY", keyDER)

	c, err := NewCA(Options{
		BaseURL:                "https://ejbca.example.test:8443/ejbca/ejbca-rest-api/v1/",
		ClientCertFile:         certPath,
		ClientKeyFile:          keyPath,
		CAName:                 "TestCA",
		CASubjectDN:            "CN=Test Root CA",
		CertificateProfileName: "ENDUSER",
		EndEntityProfileName:   "ExampleEEP",
	})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if c.baseURL != "https://ejbca.example.test:8443/ejbca/ejbca-rest-api/v1" {
		t.Errorf("baseURL = %q, want trailing slash trimmed", c.baseURL)
	}
}

func TestNewCA_MissingClientCert(t *testing.T) {
	dir := t.TempDir()
	_, err := NewCA(Options{
		BaseURL:        "https://ejbca.example.test:8443/ejbca/ejbca-rest-api/v1",
		ClientCertFile: filepath.Join(dir, "does-not-exist.crt"),
		ClientKeyFile:  filepath.Join(dir, "does-not-exist.key"),
	})
	if err == nil {
		t.Error("NewCA: expected error for missing client cert/key, got nil")
	}
}
