// Package estapi implements the RFC 7030 (EST) HTTP endpoints on top of a
// ca.CABackend and a store.Store.
package estapi

import (
	"net/http"

	"github.com/ffbarrie/est/internal/ca"
	"github.com/ffbarrie/est/internal/store"
)

// Server holds the dependencies shared by the EST HTTP handlers.
type Server struct {
	CA    ca.CABackend
	Store store.Store

	// CSRAttrsDER is the pre-encoded DER response for GET /csrattrs
	// (computed once at startup, since the response is static and
	// server-wide — see internal/csrattrs). Nil/empty means no CSR
	// attribute requirements are configured; the handler responds 204.
	CSRAttrsDER []byte
}

// NewServer constructs a Server. csrAttrsDER is the pre-encoded /csrattrs
// response body (nil if none is configured).
func NewServer(caBackend ca.CABackend, st store.Store, csrAttrsDER []byte) *Server {
	return &Server{CA: caBackend, Store: st, CSRAttrsDER: csrAttrsDER}
}

// Handler returns the http.Handler implementing the EST endpoints:
// GET /.well-known/est/cacerts, POST /.well-known/est/simpleenroll,
// POST /.well-known/est/simplereenroll, and GET /.well-known/est/csrattrs.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/est/cacerts", s.handleCACerts)
	mux.HandleFunc("POST /.well-known/est/simpleenroll", s.handleSimpleEnroll)
	mux.HandleFunc("POST /.well-known/est/simplereenroll", s.handleSimpleReenroll)
	mux.HandleFunc("GET /.well-known/est/csrattrs", s.handleCSRAttrs)
	return mux
}
