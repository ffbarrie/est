// Package ejbca implements ca.CABackend against EJBCA's REST API
// (https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface), rather
// than signing in-process (ca.LocalCA) or via a local `openssl ca`
// subprocess (internal/ca/openssl).
//
// Unlike those two backends, this one has not been verified against the
// genuine product — there was no live EJBCA instance available during
// development. The request/response shapes here are taken directly from
// EJBCA's published OpenAPI spec (Keyfactor/ejbca-ce on GitHub) and its
// official docs, and are covered by tests against a mock server shaped
// the same way, but that is not a substitute for testing against a real
// EJBCA deployment. Treat this as a verified-by-spec starting point, and
// validate it against your own instance before relying on it.
package ejbca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ffbarrie/est/internal/ca"
)

// Options configures a CA. See internal/config.EJBCACAConfig for the
// on-disk JSON shape these are translated from.
type Options struct {
	// BaseURL is EJBCA's REST API base, e.g.
	// "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1".
	BaseURL string

	// ClientCertFile/ClientKeyFile are estd's own certificate/key, used to
	// authenticate to EJBCA via TLS client certificate — the same
	// mechanism EJBCA's Admin GUI uses, mapped to an EJBCA administrator
	// role with enrollment privileges for the configured CA/profiles.
	ClientCertFile string
	ClientKeyFile  string

	// ServerCAFile is a PEM bundle of CAs trusted for EJBCA's own TLS
	// server certificate. Empty means the system trust store (suitable
	// when EJBCA's HTTPS endpoint uses a publicly-trusted certificate).
	ServerCAFile string

	// CAName is the EJBCA CA "name" used for enrollment
	// (certificate_authority_name in the pkcs10enroll request).
	CAName string

	// CASubjectDN is that same CA's Subject DN, used for the
	// /ca/{subject_dn}/certificate/download endpoint — EJBCA identifies
	// CAs differently across these two endpoints.
	CASubjectDN string

	CertificateProfileName string
	EndEntityProfileName   string
}

// CA is a ca.CABackend backed by EJBCA's REST API.
type CA struct {
	client                 *http.Client
	baseURL                string
	caName                 string
	caSubjectDN            string
	certificateProfileName string
	endEntityProfileName   string
}

// NewCA constructs a CA from opts, building an *http.Client configured
// for TLS client-certificate authentication to EJBCA.
func NewCA(opts Options) (*CA, error) {
	clientCert, err := tls.LoadX509KeyPair(opts.ClientCertFile, opts.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("ejbca: load client key pair: %w", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{clientCert}}
	if opts.ServerCAFile != "" {
		pemBytes, err := os.ReadFile(opts.ServerCAFile)
		if err != nil {
			return nil, fmt.Errorf("ejbca: read server_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ejbca: no certificates found in %s", opts.ServerCAFile)
		}
		tlsConfig.RootCAs = pool
	}

	return &CA{
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   30 * time.Second,
		},
		baseURL:                strings.TrimRight(opts.BaseURL, "/"),
		caName:                 opts.CAName,
		caSubjectDN:            opts.CASubjectDN,
		certificateProfileName: opts.CertificateProfileName,
		endEntityProfileName:   opts.EndEntityProfileName,
	}, nil
}

// errorResponse is EJBCA's documented error body shape:
// {"error_code": ..., "error_message": ...}.
type errorResponse struct {
	ErrorCode    int    `json:"error_code"`
	ErrorMessage string `json:"error_message"`
}

func httpError(statusCode int, body []byte) error {
	var er errorResponse
	if err := json.Unmarshal(body, &er); err == nil && er.ErrorMessage != "" {
		return fmt.Errorf("HTTP %d: %s (error_code %d)", statusCode, er.ErrorMessage, er.ErrorCode)
	}
	return fmt.Errorf("HTTP %d: %s", statusCode, string(body))
}

// CACertificates implements ca.CABackend by downloading the CA's
// certificate chain via GET /ca/{subject_dn}/certificate/download, which
// (per EJBCA's spec) returns the raw PEM chain directly rather than a
// JSON-wrapped body.
func (c *CA) CACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	reqURL := fmt.Sprintf("%s/ca/%s/certificate/download", c.baseURL, url.PathEscape(c.caSubjectDN))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ejbca: build CA certificate request: %w", err)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ejbca: CA certificate request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ejbca: read CA certificate response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ejbca: %w", httpError(resp.StatusCode, body))
	}

	var certs []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ejbca: parse CA certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("ejbca: no certificates found in CA certificate download response")
	}
	return certs, nil
}

// enrollRequest is EJBCA's EnrollCertificateRestRequest schema (only the
// fields this backend sets).
type enrollRequest struct {
	CertificateRequest       string `json:"certificate_request"`
	CertificateProfileName   string `json:"certificate_profile_name"`
	EndEntityProfileName     string `json:"end_entity_profile_name"`
	CertificateAuthorityName string `json:"certificate_authority_name"`
	Username                 string `json:"username"`
	Password                 string `json:"password"`
	ResponseFormat           string `json:"response_format"`
}

// enrollResponse is EJBCA's CertificateEnrollmentRestResponse schema
// (only the field this backend reads).
type enrollResponse struct {
	Certificate string `json:"certificate"`
}

// randomCredentials generates a random, one-time username/password pair
// for a single enrollment. EJBCA's pkcs10enroll enrolls against an
// end-entity identified by username/password; this assumes the operator's
// End Entity Profile permits ad hoc/self-service enrollment with
// arbitrary credentials, which is not universal across EJBCA deployments
// — see the package doc and README for this caveat.
func randomCredentials() (username, password string, err error) {
	userBuf := make([]byte, 8)
	if _, err := rand.Read(userBuf); err != nil {
		return "", "", fmt.Errorf("generate username: %w", err)
	}
	passBuf := make([]byte, 24)
	if _, err := rand.Read(passBuf); err != nil {
		return "", "", fmt.Errorf("generate password: %w", err)
	}
	return "estd-" + hex.EncodeToString(userBuf), hex.EncodeToString(passBuf), nil
}

// IssueCertificate implements ca.CABackend via POST /certificate/pkcs10enroll.
func (c *CA) IssueCertificate(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, ca.ErrInvalidCSRSignature
	}

	username, password, err := randomCredentials()
	if err != nil {
		return nil, fmt.Errorf("ejbca: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})

	reqBody, err := json.Marshal(enrollRequest{
		CertificateRequest:       string(csrPEM),
		CertificateProfileName:   c.certificateProfileName,
		EndEntityProfileName:     c.endEntityProfileName,
		CertificateAuthorityName: c.caName,
		Username:                 username,
		Password:                 password,
		ResponseFormat:           "DER",
	})
	if err != nil {
		return nil, fmt.Errorf("ejbca: marshal enroll request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/certificate/pkcs10enroll", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("ejbca: build enroll request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ejbca: enroll request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ejbca: read enroll response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ejbca: %w", httpError(resp.StatusCode, body))
	}

	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		return nil, fmt.Errorf("ejbca: unmarshal enroll response: %w", err)
	}

	der, err := base64.StdEncoding.DecodeString(er.Certificate)
	if err != nil {
		return nil, fmt.Errorf("ejbca: base64-decode issued certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ejbca: parse issued certificate: %w", err)
	}

	// Defense-in-depth: never hand back a CA certificate, even if the
	// operator's EJBCA certificate profile is misconfigured — same
	// backstop as internal/ca/openssl.
	if cert.IsCA {
		return nil, fmt.Errorf("ejbca: issued certificate has CA:TRUE; check the %q certificate profile", c.certificateProfileName)
	}

	return cert, nil
}

var _ ca.CABackend = (*CA)(nil)
