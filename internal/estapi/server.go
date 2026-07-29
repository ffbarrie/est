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
}

// NewServer constructs a Server.
func NewServer(caBackend ca.CABackend, st store.Store) *Server {
	return &Server{CA: caBackend, Store: st}
}

// Handler returns the http.Handler implementing the v1 EST endpoints:
// GET /.well-known/est/cacerts, POST /.well-known/est/simpleenroll and
// POST /.well-known/est/simplereenroll.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/est/cacerts", s.handleCACerts)
	mux.HandleFunc("POST /.well-known/est/simpleenroll", s.handleSimpleEnroll)
	mux.HandleFunc("POST /.well-known/est/simplereenroll", s.handleSimpleReenroll)
	return mux
}
