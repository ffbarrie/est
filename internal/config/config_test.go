package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoad_ValidConfig(t *testing.T) {
	c, err := Load(writeConfig(t, t.TempDir(), "config.json", `{
		"listen_addr": ":8443",
		"server_cert_file": "server.crt",
		"server_key_file": "server.key",
		"client_ca_files": ["ca.crt"],
		"ca_cert_file": "ca.crt",
		"ca_key_file": "ca.key",
		"store_dir": "./data",
		"cert_validity": "8760h"
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenAddr != ":8443" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
	if time.Duration(c.CertValidity) != 8760*time.Hour {
		t.Errorf("CertValidity = %v, want 8760h", time.Duration(c.CertValidity))
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Error("Load: expected error for missing file, got nil")
	}
}

func TestLoad_MalformedDuration(t *testing.T) {
	_, err := Load(writeConfig(t, t.TempDir(), "config.json", `{"cert_validity": "not-a-duration"}`))
	if err == nil {
		t.Error("Load: expected error for malformed duration, got nil")
	}
}

func TestValidate_MissingRequiredField(t *testing.T) {
	c := &Config{
		ServerCertFile: "x",
		ServerKeyFile:  "x",
		ClientCAFiles:  []string{"x"},
		CACertFile:     "x",
		CAKeyFile:      "x",
		StoreDir:       "x",
		CertValidity:   Duration(time.Hour),
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for missing listen_addr, got nil")
	}
}

func TestValidate_NoClientCAFiles(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr:     ":8443",
		ServerCertFile: f,
		ServerKeyFile:  f,
		CACertFile:     f,
		CAKeyFile:      f,
		StoreDir:       dir,
		CertValidity:   Duration(time.Hour),
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for empty client_ca_files, got nil")
	}
}

func TestValidate_NonexistentReferencedFile(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr:     ":8443",
		ServerCertFile: filepath.Join(dir, "missing.crt"),
		ServerKeyFile:  f,
		ClientCAFiles:  []string{f},
		CACertFile:     f,
		CAKeyFile:      f,
		StoreDir:       dir,
		CertValidity:   Duration(time.Hour),
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for nonexistent server_cert_file, got nil")
	}
}

func TestValidate_NonPositiveCertValidity(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr:     ":8443",
		ServerCertFile: f,
		ServerKeyFile:  f,
		ClientCAFiles:  []string{f},
		CACertFile:     f,
		CAKeyFile:      f,
		StoreDir:       dir,
		CertValidity:   Duration(0),
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for zero cert_validity, got nil")
	}
}

func TestValidate_OK(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr:     ":8443",
		ServerCertFile: f,
		ServerKeyFile:  f,
		ClientCAFiles:  []string{f},
		CACertFile:     f,
		CAKeyFile:      f,
		StoreDir:       dir,
		CertValidity:   Duration(time.Hour),
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: unexpected error: %v", err)
	}
}
