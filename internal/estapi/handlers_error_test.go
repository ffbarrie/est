package estapi

import (
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"testing"

	"github.com/ffbarrie/est/internal/ca"
	"github.com/ffbarrie/est/internal/store"
)

func TestHandleCACerts_BackendError(t *testing.T) {
	tc := newTestCA(t)
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	ts := newTestServerWithBackends(t, tc, &fakeCABackend{caCertsErr: errors.New("ca backend unavailable")}, st)
	client := clientFor(t, ts, nil, nil)

	resp, err := client.Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatalf("GET /cacerts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleCACerts_EncodeError(t *testing.T) {
	tc := newTestCA(t)
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// A certificate with no Raw DER makes pkcs7.EncodeCertsOnly fail,
	// covering the encode-error branch distinctly from a backend error.
	ts := newTestServerWithBackends(t, tc, &fakeCABackend{caCerts: []*x509.Certificate{{}}}, st)
	client := clientFor(t, ts, nil, nil)

	resp, err := client.Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatalf("GET /cacerts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleSimpleEnroll_IssueCertificateGenericError(t *testing.T) {
	tc := newTestCA(t)
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	ts := newTestServerWithBackends(t, tc, &fakeCABackend{issueErr: errors.New("ca unavailable")}, st)
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "device.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleSimpleEnroll_InvalidCSRSignatureMapsTo400(t *testing.T) {
	tc := newTestCA(t)
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// Exercises the handler's errors.Is(err, ca.ErrInvalidCSRSignature) ->
	// 400 mapping directly, independent of internal/ca's own tests proving
	// LocalCA itself detects a bad signature.
	ts := newTestServerWithBackends(t, tc, &fakeCABackend{issueErr: ca.ErrInvalidCSRSignature}, st)
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "device.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleSimpleEnroll_StorePutCSRError(t *testing.T) {
	tc := newTestCA(t)
	issueCert, _ := tc.issueLeaf(t, "device.example.test")
	ts := newTestServerWithBackends(t, tc, &fakeCABackend{issueCert: issueCert}, &fakeStore{putCSRErr: errors.New("disk full")})
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "device.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleSimpleEnroll_StorePutCertificateError(t *testing.T) {
	tc := newTestCA(t)
	issueCert, _ := tc.issueLeaf(t, "device.example.test")
	ts := newTestServerWithBackends(t, tc, &fakeCABackend{issueCert: issueCert}, &fakeStore{putCertErr: errors.New("disk full")})
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "device.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleSimpleEnroll_EncodeIssuedCertificateError(t *testing.T) {
	tc := newTestCA(t)
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// An issued certificate with no Raw DER makes pkcs7.EncodeCertsOnly
	// fail after the store writes have already succeeded. SerialNumber
	// must still be set — the store keys files by serial number.
	ts := newTestServerWithBackends(t, tc, &fakeCABackend{issueCert: &x509.Certificate{SerialNumber: big.NewInt(1)}}, st)
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10,
		newBase64Reader(csrDER(t, "device.example.test", nil)))
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}
