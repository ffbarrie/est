package estapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http/httptest"
	"testing"

	"github.com/ffbarrie/est/internal/ca"
	"github.com/ffbarrie/est/internal/store"
)

// fakeCABackend is a ca.CABackend test double letting tests inject
// failures the real LocalCA can't easily be made to produce, so the
// handler's error-handling branches (as opposed to the CA's) get covered.
type fakeCABackend struct {
	caCerts    []*x509.Certificate
	caCertsErr error
	issueCert  *x509.Certificate
	issueErr   error
}

func (f *fakeCABackend) CACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	if f.caCertsErr != nil {
		return nil, f.caCertsErr
	}
	return f.caCerts, nil
}

func (f *fakeCABackend) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	return f.issueCert, nil
}

// fakeStore is a store.Store test double that can be made to fail on
// Put*, to cover handler error branches the real FileStore rarely hits.
type fakeStore struct {
	putCSRErr  error
	putCertErr error
}

func (f *fakeStore) PutCSR(ctx context.Context, serial *big.Int, csrDER []byte, meta store.Metadata) error {
	return f.putCSRErr
}

func (f *fakeStore) PutCertificate(ctx context.Context, serial *big.Int, certDER []byte, meta store.Metadata) error {
	return f.putCertErr
}

func (f *fakeStore) GetCertificate(ctx context.Context, serial *big.Int) (*x509.Certificate, error) {
	return nil, errors.New("fakeStore: not implemented")
}

// newTestServerWithBackends is newTestServer's counterpart for tests that
// need to inject a fake CABackend/Store to exercise handler error paths.
// Client certificates are still trusted via tc, independent of which
// backend issues certificates.
func newTestServerWithBackends(t *testing.T, tc testCA, caBackend ca.CABackend, st store.Store) *httptest.Server {
	t.Helper()
	srv := NewServer(caBackend, st, nil)

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
