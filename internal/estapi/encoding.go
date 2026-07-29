package estapi

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	contentTypePKCS10    = "application/pkcs10"
	contentTypePKCS7Mime = "application/pkcs7-mime; smime-type=certs-only"

	// maxCSRBodyBytes caps the base64-encoded request body EST clients may
	// send to /simpleenroll and /simplereenroll.
	maxCSRBodyBytes = 64 * 1024

	// mimeLineLength is the standard base64 MIME line length (RFC 2045),
	// used when wrapping base64 responses.
	mimeLineLength = 76
)

// decodeCSRBody reads a base64-encoded, DER-encoded PKCS#10 CSR from an EST
// request body (Content-Type: application/pkcs10). Per RFC 8951 §3, the
// body is base64 [RFC4648] regardless of any Content-Transfer-Encoding
// header, so no such header is inspected here.
func decodeCSRBody(r *http.Request) (*x509.CertificateRequest, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCSRBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if len(body) > maxCSRBodyBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxCSRBodyBytes)
	}

	der, err := base64.StdEncoding.DecodeString(stripWhitespace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("base64-decode request body: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, nil
}

func stripWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// writePKCS7Response writes der as a base64-encoded, MIME-wrapped
// (76 chars/line, CRLF) application/pkcs7-mime response body, per RFC
// 7030's certs-only response format. No Content-Transfer-Encoding header is
// sent: RFC 8951 §3 retires that header from the spec text in favor of
// plain base64 [RFC4648], and requires any value in it to be ignored.
func writePKCS7Response(w http.ResponseWriter, der []byte) {
	encoded := base64.StdEncoding.EncodeToString(der)

	w.Header().Set("Content-Type", contentTypePKCS7Mime)
	w.WriteHeader(http.StatusOK)

	for i := 0; i < len(encoded); i += mimeLineLength {
		end := i + mimeLineLength
		if end > len(encoded) {
			end = len(encoded)
		}
		io.WriteString(w, encoded[i:end])
		io.WriteString(w, "\r\n")
	}
}
