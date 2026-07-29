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

func TestLoad_CSRAttrs(t *testing.T) {
	c, err := Load(writeConfig(t, t.TempDir(), "config.json", `{
		"listen_addr": ":8443",
		"server_cert_file": "server.crt",
		"server_key_file": "server.key",
		"client_ca_files": ["ca.crt"],
		"ca_cert_file": "ca.crt",
		"ca_key_file": "ca.key",
		"store_dir": "./data",
		"cert_validity": "8760h",
		"csr_attrs": {
			"challenge_password": true,
			"key_algorithm": {"oid": "1.2.840.10045.2.1", "curve_oid": "1.3.132.0.34"},
			"required_extensions": [
				{"oid": "2.5.29.17", "critical": true, "value_hex": "3009820777772e636f6d"}
			],
			"extra_oids": ["1.2.840.10045.4.3.3"],
			"template": {
				"subject": [
					{"oid": "2.5.4.3"},
					{"oid": "2.5.4.11", "value": "myDept"}
				],
				"key_type": {"oid": "1.2.840.10045.2.1", "curve_oid": "1.2.840.10045.3.1.7"},
				"extensions": [
					{"oid": "2.5.29.17"},
					{"oid": "2.5.29.15", "critical": true, "value_hex": "0500"}
				]
			}
		}
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CSRAttrs == nil {
		t.Fatal("CSRAttrs is nil")
	}
	if !c.CSRAttrs.ChallengePassword {
		t.Error("ChallengePassword = false, want true")
	}
	if c.CSRAttrs.KeyAlgorithm == nil || c.CSRAttrs.KeyAlgorithm.CurveOID != "1.3.132.0.34" {
		t.Errorf("KeyAlgorithm = %+v", c.CSRAttrs.KeyAlgorithm)
	}
	if len(c.CSRAttrs.RequiredExtensions) != 1 || c.CSRAttrs.RequiredExtensions[0].OID != "2.5.29.17" {
		t.Errorf("RequiredExtensions = %+v", c.CSRAttrs.RequiredExtensions)
	}
	if len(c.CSRAttrs.ExtraOIDs) != 1 || c.CSRAttrs.ExtraOIDs[0] != "1.2.840.10045.4.3.3" {
		t.Errorf("ExtraOIDs = %+v", c.CSRAttrs.ExtraOIDs)
	}
	tmpl := c.CSRAttrs.Template
	if tmpl == nil {
		t.Fatal("Template is nil")
	}
	if len(tmpl.Subject) != 2 {
		t.Fatalf("Template.Subject has %d entries, want 2", len(tmpl.Subject))
	}
	if tmpl.Subject[0].Value != nil {
		t.Errorf("Subject[0].Value = %v, want nil", *tmpl.Subject[0].Value)
	}
	if tmpl.Subject[1].Value == nil || *tmpl.Subject[1].Value != "myDept" {
		t.Errorf("Subject[1].Value = %v, want \"myDept\"", tmpl.Subject[1].Value)
	}
	if len(tmpl.Extensions) != 2 {
		t.Fatalf("Template.Extensions has %d entries, want 2", len(tmpl.Extensions))
	}
	if tmpl.Extensions[0].ValueHex != nil {
		t.Errorf("Extensions[0].ValueHex = %v, want nil", *tmpl.Extensions[0].ValueHex)
	}
	if tmpl.Extensions[1].ValueHex == nil || *tmpl.Extensions[1].ValueHex != "0500" {
		t.Errorf("Extensions[1].ValueHex = %v, want \"0500\"", tmpl.Extensions[1].ValueHex)
	}
}

func TestLoad_CSRAttrsAbsent(t *testing.T) {
	c, err := Load(writeConfig(t, t.TempDir(), "config.json", `{
		"listen_addr": ":8443",
		"cert_validity": "8760h"
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CSRAttrs != nil {
		t.Errorf("CSRAttrs = %+v, want nil when absent from config", c.CSRAttrs)
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
	if c.CABackend != "local" {
		t.Errorf("CABackend = %q, want normalized \"local\"", c.CABackend)
	}
}

func TestValidate_InvalidCABackend(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		CACertFile: f, CAKeyFile: f, StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "bogus",
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for invalid ca_backend, got nil")
	}
}

func TestValidate_LocalBackendRequiresCAKeyFile(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		CACertFile: f, StoreDir: dir, CertValidity: Duration(time.Hour),
		// CAKeyFile deliberately omitted; CABackend defaults to "local".
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for missing ca_key_file under local backend, got nil")
	}
}

func TestValidate_OpenSSLBackend_OK(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	cnf := writeConfig(t, dir, "openssl.cnf", "[ca]\n")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		CACertFile: f, StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "openssl",
		OpenSSLCA: &OpenSSLCAConfig{ConfigFile: cnf},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if c.OpenSSLCA.OpenSSLPath != "openssl" {
		t.Errorf("OpenSSLPath = %q, want normalized \"openssl\"", c.OpenSSLCA.OpenSSLPath)
	}
	if c.OpenSSLCA.ExtensionsSection != "est_extensions" {
		t.Errorf("ExtensionsSection = %q, want normalized \"est_extensions\"", c.OpenSSLCA.ExtensionsSection)
	}
	// ca_key_file is not required (and was never set above) under the
	// openssl backend.
}

func TestValidate_OpenSSLBackend_RequiresOpenSSLCA(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		CACertFile: f, StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "openssl",
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for missing openssl_ca, got nil")
	}
}

func TestValidate_OpenSSLBackend_MissingConfigFile(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		CACertFile: f, StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "openssl",
		OpenSSLCA: &OpenSSLCAConfig{ConfigFile: filepath.Join(dir, "does-not-exist.cnf")},
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for nonexistent openssl_ca.config_file, got nil")
	}
}

func TestValidate_OpenSSLBackend_MissingBinary(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	cnf := writeConfig(t, dir, "openssl.cnf", "[ca]\n")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		CACertFile: f, StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "openssl",
		OpenSSLCA: &OpenSSLCAConfig{ConfigFile: cnf, OpenSSLPath: "/no/such/openssl-binary"},
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for unresolvable openssl_path, got nil")
	}
}

func validEJBCACAConfig(f string) *EJBCACAConfig {
	return &EJBCACAConfig{
		BaseURL:                "https://ejbca.example.test:8443/ejbca/ejbca-rest-api/v1",
		ClientCertFile:         f,
		ClientKeyFile:          f,
		CAName:                 "TestCA",
		CASubjectDN:            "CN=Test Root CA",
		CertificateProfileName: "ENDUSER",
		EndEntityProfileName:   "ExampleEEP",
	}
}

func TestValidate_EJBCABackend_OK(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "ejbca",
		EJBCACA:   validEJBCACAConfig(f),
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: unexpected error: %v", err)
	}
	// ca_cert_file/ca_key_file are not needed under the ejbca backend and
	// were never set above.
}

func TestValidate_EJBCABackend_RequiresEJBCACA(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "ejbca",
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for missing ejbca_ca, got nil")
	}
}

func TestValidate_EJBCABackend_MissingRequiredField(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	e := validEJBCACAConfig(f)
	e.CASubjectDN = ""
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "ejbca",
		EJBCACA:   e,
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for missing ejbca_ca.ca_subject_dn, got nil")
	}
}

func TestValidate_EJBCABackend_MissingClientCertFile(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	e := validEJBCACAConfig(f)
	e.ClientCertFile = filepath.Join(dir, "does-not-exist.crt")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "ejbca",
		EJBCACA:   e,
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for nonexistent ejbca_ca.client_cert_file, got nil")
	}
}

func TestValidate_EJBCABackend_ServerCAFileMustExistIfSet(t *testing.T) {
	dir := t.TempDir()
	f := writeConfig(t, dir, "f.pem", "x")
	e := validEJBCACAConfig(f)
	e.ServerCAFile = filepath.Join(dir, "does-not-exist.crt")
	c := &Config{
		ListenAddr: ":8443", ServerCertFile: f, ServerKeyFile: f, ClientCAFiles: []string{f},
		StoreDir: dir, CertValidity: Duration(time.Hour),
		CABackend: "ejbca",
		EJBCACA:   e,
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for nonexistent ejbca_ca.server_ca_file, got nil")
	}
}
