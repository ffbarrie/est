package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func genTestCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "store-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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

func TestFileStore_PutGetRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "store")
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("store dir not created: %v", err)
	}

	serial := big.NewInt(0xABCDEF)
	cert := genTestCert(t, 42)
	meta := Metadata{Requester: "client01", RemoteAddr: "192.0.2.1:1234", ReceivedAt: time.Now()}

	if err := fs.PutCSR(context.Background(), serial, []byte("fake csr der"), meta); err != nil {
		t.Fatalf("PutCSR: %v", err)
	}
	if err := fs.PutCertificate(context.Background(), serial, cert.Raw, meta); err != nil {
		t.Fatalf("PutCertificate: %v", err)
	}

	got, err := fs.GetCertificate(context.Background(), serial)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("SerialNumber = %v, want %v", got.SerialNumber, cert.SerialNumber)
	}

	csrDER, err := os.ReadFile(fs.csrPath(serial))
	if err != nil {
		t.Fatalf("read csr file: %v", err)
	}
	if string(csrDER) != "fake csr der" {
		t.Errorf("csr file contents = %q", csrDER)
	}

	metaJSON, err := os.ReadFile(fs.certMetaPath(serial))
	if err != nil {
		t.Fatalf("read metadata file: %v", err)
	}
	if !strings.Contains(string(metaJSON), "client01") {
		t.Errorf("metadata file missing requester: %s", metaJSON)
	}
}

func TestFileStore_GetCertificate_NotFound(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, err := fs.GetCertificate(context.Background(), big.NewInt(999)); err == nil {
		t.Error("GetCertificate for missing serial: expected error, got nil")
	}
}

func TestFileStore_ConcurrentPuts(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			serial := big.NewInt(int64(i + 1))
			cert := genTestCert(t, int64(i+1))
			meta := Metadata{Requester: "concurrent", ReceivedAt: time.Now()}
			if err := fs.PutCertificate(context.Background(), serial, cert.Raw, meta); err != nil {
				t.Errorf("PutCertificate(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		serial := big.NewInt(int64(i + 1))
		if _, err := fs.GetCertificate(context.Background(), serial); err != nil {
			t.Errorf("GetCertificate(%d): %v", i, err)
		}
	}

	// No leaked temp files after all writes complete.
	entries, err := os.ReadDir(filepath.Join(fs.dir, "certs"))
	if err != nil {
		t.Fatalf("read certs dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leaked temp file: %s", e.Name())
		}
	}
}
