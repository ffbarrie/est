package estapi

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeTestPEM(t *testing.T, path, blockType string, der []byte) {
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

func TestBuildTLSConfig_Success(t *testing.T) {
	tc := newTestCA(t)
	serverCert, serverKey := tc.issueLeaf(t, "est.example.test")

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	writeTestPEM(t, caPath, "CERTIFICATE", tc.cert.Raw)
	writeTestPEM(t, certPath, "CERTIFICATE", serverCert.Raw)

	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	writeTestPEM(t, keyPath, "PRIVATE KEY", keyDER)

	tlsConfig, err := BuildTLSConfig(certPath, keyPath, []string{caPath})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(tlsConfig.Certificates))
	}
	if tlsConfig.ClientCAs == nil || len(tlsConfig.ClientCAs.Subjects()) != 1 { //nolint:staticcheck // Subjects() is fine for a test assertion
		t.Fatalf("ClientCAs pool does not contain exactly one CA")
	}
}

func TestBuildTLSConfig_MissingServerCert(t *testing.T) {
	tc := newTestCA(t)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	writeTestPEM(t, caPath, "CERTIFICATE", tc.cert.Raw)

	_, err := BuildTLSConfig(filepath.Join(dir, "does-not-exist.crt"), filepath.Join(dir, "does-not-exist.key"), []string{caPath})
	if err == nil {
		t.Error("BuildTLSConfig: expected error for missing server cert/key, got nil")
	}
}

func TestBuildTLSConfig_MissingCABundle(t *testing.T) {
	tc := newTestCA(t)
	serverCert, serverKey := tc.issueLeaf(t, "est.example.test")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	writeTestPEM(t, certPath, "CERTIFICATE", serverCert.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	writeTestPEM(t, keyPath, "PRIVATE KEY", keyDER)

	_, err = BuildTLSConfig(certPath, keyPath, []string{filepath.Join(dir, "does-not-exist-ca.crt")})
	if err == nil {
		t.Error("BuildTLSConfig: expected error for missing CA bundle file, got nil")
	}
}

func TestBuildTLSConfig_EmptyCABundle(t *testing.T) {
	tc := newTestCA(t)
	serverCert, serverKey := tc.issueLeaf(t, "est.example.test")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	emptyCAPath := filepath.Join(dir, "empty.crt")

	writeTestPEM(t, certPath, "CERTIFICATE", serverCert.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	writeTestPEM(t, keyPath, "PRIVATE KEY", keyDER)
	if err := os.WriteFile(emptyCAPath, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write empty CA bundle: %v", err)
	}

	_, err = BuildTLSConfig(certPath, keyPath, []string{emptyCAPath})
	if err == nil {
		t.Error("BuildTLSConfig: expected error for a CA bundle file with no certificates, got nil")
	}
}
