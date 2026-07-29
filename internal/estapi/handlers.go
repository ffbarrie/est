package estapi

import (
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ffbarrie/est/internal/ca"
	"github.com/ffbarrie/est/internal/pkcs7"
	"github.com/ffbarrie/est/internal/store"
)

// handleCACerts implements GET /.well-known/est/cacerts. No client
// certificate is required (see BuildTLSConfig): this is EST's bootstrap
// endpoint for clients that don't have one yet.
func (s *Server) handleCACerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.CA.CACertificates(r.Context())
	if err != nil {
		slog.Error("cacerts: backend error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	der, err := pkcs7.EncodeCertsOnly(certs)
	if err != nil {
		slog.Error("cacerts: encode error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writePKCS7Response(w, der)
}

// handleSimpleEnroll implements POST /.well-known/est/simpleenroll. Per the
// v1 auth decision, the client must present an mTLS certificate the server
// already trusts (there is no HTTP Basic/Digest fallback).
func (s *Server) handleSimpleEnroll(w http.ResponseWriter, r *http.Request) {
	peer, err := peerCertificate(r)
	if err != nil {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}

	csr, err := decodeCSRBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.issueAndRespond(w, r, csr, peer)
}

// handleSimpleReenroll implements POST /.well-known/est/simplereenroll. The
// CSR's identity must match the authenticated client certificate's
// identity (see identitiesMatch); anything else is rejected.
func (s *Server) handleSimpleReenroll(w http.ResponseWriter, r *http.Request) {
	peer, err := peerCertificate(r)
	if err != nil {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}

	csr, err := decodeCSRBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !identitiesMatch(peer, csr) {
		http.Error(w, "CSR identity does not match authenticated client certificate", http.StatusForbidden)
		return
	}

	s.issueAndRespond(w, r, csr, peer)
}

// issueAndRespond signs csr via the CA backend, persists the CSR and
// issued certificate, and writes the certs-only PKCS#7 response. peer is
// the authenticated client certificate, recorded in the stored metadata.
func (s *Server) issueAndRespond(w http.ResponseWriter, r *http.Request, csr *x509.CertificateRequest, peer *x509.Certificate) {
	cert, err := s.CA.IssueCertificate(r.Context(), csr)
	if err != nil {
		if errors.Is(err, ca.ErrInvalidCSRSignature) {
			http.Error(w, "CSR signature does not verify", http.StatusBadRequest)
			return
		}
		slog.Error("issue certificate: backend error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	meta := store.Metadata{
		Requester:  peer.Subject.CommonName,
		RemoteAddr: r.RemoteAddr,
		ReceivedAt: time.Now(),
	}
	if err := s.Store.PutCSR(r.Context(), cert.SerialNumber, csr.Raw, meta); err != nil {
		slog.Error("persist CSR", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.PutCertificate(r.Context(), cert.SerialNumber, cert.Raw, meta); err != nil {
		slog.Error("persist certificate", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	der, err := pkcs7.EncodeCertsOnly([]*x509.Certificate{cert})
	if err != nil {
		slog.Error("encode issued certificate", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writePKCS7Response(w, der)
}
