// Command estd runs an EST (RFC 7030) server backed by a pluggable
// ca.CABackend — a local, crypto/x509-based CA by default, or a real
// `openssl ca` command-line CA when configured (see ca_backend in
// internal/config).
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ffbarrie/est/internal/ca"
	ejbcaca "github.com/ffbarrie/est/internal/ca/ejbca"
	opensslca "github.com/ffbarrie/est/internal/ca/openssl"
	"github.com/ffbarrie/est/internal/config"
	"github.com/ffbarrie/est/internal/csrattrs"
	"github.com/ffbarrie/est/internal/estapi"
	"github.com/ffbarrie/est/internal/store"
)

func main() {
	configPath := flag.String("config", "", "path to JSON config file")
	flag.Parse()

	if *configPath == "" {
		slog.Error("missing required -config flag")
		os.Exit(1)
	}

	if err := run(*configPath); err != nil {
		slog.Error("estd exiting", "err", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	var caBackend ca.CABackend
	switch cfg.CABackend {
	case "openssl":
		caCert, err := opensslca.LoadCACertificate(cfg.CACertFile)
		if err != nil {
			return err
		}
		caBackend = opensslca.NewCA(cfg.OpenSSLCA.OpenSSLPath, cfg.OpenSSLCA.ConfigFile, caCert, cfg.OpenSSLCA.ExtensionsSection)
	case "ejbca":
		e := cfg.EJBCACA
		caBackend, err = ejbcaca.NewCA(ejbcaca.Options{
			BaseURL:                e.BaseURL,
			ClientCertFile:         e.ClientCertFile,
			ClientKeyFile:          e.ClientKeyFile,
			ServerCAFile:           e.ServerCAFile,
			CAName:                 e.CAName,
			CASubjectDN:            e.CASubjectDN,
			CertificateProfileName: e.CertificateProfileName,
			EndEntityProfileName:   e.EndEntityProfileName,
		})
		if err != nil {
			return err
		}
	default: // "local", normalized by cfg.Validate
		caCert, caKey, err := ca.LoadCAKeyPair(cfg.CACertFile, cfg.CAKeyFile)
		if err != nil {
			return err
		}
		caBackend = ca.NewLocalCA(caCert, caKey, ca.RandomSerialSource{}, time.Duration(cfg.CertValidity))
	}

	fileStore, err := store.NewFileStore(cfg.StoreDir)
	if err != nil {
		return err
	}

	tlsConfig, err := estapi.BuildTLSConfig(cfg.ServerCertFile, cfg.ServerKeyFile, cfg.ClientCAFiles)
	if err != nil {
		return err
	}

	csrAttrsDER, err := csrattrs.Encode(csrAttrsOptions(cfg.CSRAttrs))
	if err != nil {
		return err
	}

	srv := estapi.NewServer(caBackend, fileStore, csrAttrsDER)

	httpServer := &http.Server{
		Addr:      cfg.ListenAddr,
		Handler:   srv.Handler(),
		TLSConfig: tlsConfig,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("estd listening", "addr", cfg.ListenAddr)
		errCh <- httpServer.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		slog.Info("estd shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	return nil
}
