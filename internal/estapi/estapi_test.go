package estapi

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ffbarrie/est/internal/ca"
	"github.com/ffbarrie/est/internal/csrattrs"
	"github.com/ffbarrie/est/internal/pkcs7"
	"github.com/ffbarrie/est/internal/store"
)

// testCA bundles a self-signed CA cert/key used as both the issuing CA and
// the mTLS client-trust anchor in these tests.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return testCA{cert: cert, key: key}
}

// issueLeaf signs a leaf certificate for cn directly with the test CA (used
// to mint the mTLS client certificate presented in these tests, separately
// from certificates issued through the EST endpoints themselves).
func (tc testCA) issueLeaf(t *testing.T, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tc.cert, key.Public(), tc.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert, key
}

func csrDER(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

// newTestServer starts an httptest.Server with real mTLS (VerifyClientCertIfGiven)
// backed by a LocalCA rooted at tc, and returns it along with the file
// store directory it uses.
func newTestServer(t *testing.T, tc testCA, csrAttrsDER []byte) *httptest.Server {
	t.Helper()

	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	localCA := ca.NewLocalCA(tc.cert, tc.key, ca.RandomSerialSource{}, time.Hour)
	srv := NewServer(localCA, st, csrAttrsDER)

	ts := httptest.NewUnstartedServer(srv.Handler())

	pool := x509.NewCertPool()
	pool.AddCert(tc.cert)
	ts.TLS = &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func clientFor(t *testing.T, ts *httptest.Server, leafCert *x509.Certificate, leafKey crypto.Signer) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())

	tlsConfig := &tls.Config{RootCAs: pool}
	if leafCert != nil {
		tlsConfig.Certificates = []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafKey,
		}}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
}

func TestHandleCACerts_NoClientCertRequired(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	client := clientFor(t, ts, nil, nil)

	resp, err := client.Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatalf("GET /cacerts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(stripWhitespace(string(body)))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	certs, err := pkcs7.DecodeCertsOnly(der)
	if err != nil {
		t.Fatalf("decode pkcs7: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "Test Root CA" {
		t.Fatalf("certs = %v", certs)
	}
}

// TestMTLS_UntrustedClientCertRejected proves the core mTLS security
// property that every other test only exercises indirectly: a client
// certificate signed by a CA the server does NOT trust must be rejected
// at the TLS handshake, not merely treated as "no certificate presented".
// This differs from TestHandleSimpleEnroll_RequiresClientCert (no cert at
// all, handshake succeeds, handler returns 401) — here the handshake
// itself must fail, for every endpoint, including ones that don't
// otherwise require a client certificate.
func TestMTLS_UntrustedClientCertRejected(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)

	untrustedCA := newTestCA(t) // independent root, not in the server's ClientCAs pool
	leafCert, leafKey := untrustedCA.issueLeaf(t, "impostor.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	// /cacerts doesn't itself require a client certificate, but presenting
	// an untrusted one must still fail the handshake before any HTTP
	// routing happens (tls.VerifyClientCertIfGiven verifies whatever is
	// presented, unconditionally).
	_, err := client.Get(ts.URL + "/.well-known/est/cacerts")
	if err == nil {
		t.Fatal("expected TLS handshake to fail for a client cert signed by an untrusted CA, got nil error")
	}
}

func TestHandleSimpleEnroll_RequiresClientCert(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	client := clientFor(t, ts, nil, nil)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "device01.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandleSimpleEnroll_IssuesCertificate(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "device02.example.test", []string{"device02.example.test"})))
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	der, err := base64.StdEncoding.DecodeString(stripWhitespace(string(body)))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	certs, err := pkcs7.DecodeCertsOnly(der)
	if err != nil {
		t.Fatalf("decode pkcs7: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "device02.example.test" {
		t.Fatalf("issued cert = %v", certs)
	}
}

func TestHandleSimpleReenroll_IdentityMismatchRejected(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	leafCert, leafKey := tc.issueLeaf(t, "client01.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simplereenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "someone-else.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simplereenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandleSimpleReenroll_MatchingIdentityIssues(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	leafCert, leafKey := tc.issueLeaf(t, "client01.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simplereenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "client01.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simplereenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}
}

func TestHandleSimpleEnroll_MalformedBody(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader([]byte("this is not a CSR")))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	}
}

func TestHandleCSRAttrs_NoneConfigured(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	client := clientFor(t, ts, nil, nil)

	resp, err := client.Get(ts.URL + "/.well-known/est/csrattrs")
	if err != nil {
		t.Fatalf("GET /csrattrs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

func TestHandleCSRAttrs_Configured(t *testing.T) {
	tc := newTestCA(t)
	der, err := csrattrs.Encode(csrattrs.Options{ChallengePassword: true})
	if err != nil {
		t.Fatalf("csrattrs.Encode: %v", err)
	}
	ts := newTestServer(t, tc, der)
	client := clientFor(t, ts, nil, nil) // no client cert — RFC 7030 §4.5 SHOULD NOT require one

	resp, err := client.Get(ts.URL + "/.well-known/est/csrattrs")
	if err != nil {
		t.Fatalf("GET /csrattrs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != contentTypeCSRAttrs {
		t.Errorf("Content-Type = %q, want %q", ct, contentTypeCSRAttrs)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(stripWhitespace(string(body)))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Errorf("body = %x, want %x", got, der)
	}
}

// newBase64Reader base64-encodes der the way an EST client would before
// sending it as the request body.
func newBase64Reader(der []byte) io.Reader {
	return strings.NewReader(base64.StdEncoding.EncodeToString(der))
}
