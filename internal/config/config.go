// Package config loads and validates the JSON configuration file for the
// EST server binary.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Duration wraps time.Duration so it can be read from and written to JSON
// as a string (e.g. "8760h") via encoding/json, without a third-party
// dependency.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Config is the on-disk JSON configuration for estd.
type Config struct {
	ListenAddr     string   `json:"listen_addr"`
	ServerCertFile string   `json:"server_cert_file"`
	ServerKeyFile  string   `json:"server_key_file"`
	ClientCAFiles  []string `json:"client_ca_files"`
	CACertFile     string   `json:"ca_cert_file"`
	StoreDir       string   `json:"store_dir"`
	CertValidity   Duration `json:"cert_validity"`

	// CABackend selects which ca.CABackend implementation signs
	// certificates: "local" (default, crypto/x509-based, in-process — the
	// only mode that reads CAKeyFile) or "openssl" (shells out to a real
	// `openssl ca`; see OpenSSLCA). Validate normalizes "" to "local".
	CABackend string `json:"ca_backend,omitempty"`

	// CAKeyFile is only read/required when CABackend is "local".
	CAKeyFile string `json:"ca_key_file,omitempty"`

	// OpenSSLCA configures the openssl-backed CABackend. Required when
	// CABackend is "openssl"; ignored otherwise.
	OpenSSLCA *OpenSSLCAConfig `json:"openssl_ca,omitempty"`

	// CSRAttrs configures the GET /csrattrs response. Nil means the server
	// has no CSR attribute requirements to advertise (responds 204).
	CSRAttrs *CSRAttrsConfig `json:"csr_attrs,omitempty"`
}

// OpenSSLCAConfig configures the openssl-backed CABackend
// (internal/ca/openssl). See openssl-ca.example.cnf at the repo root for
// the required openssl.cnf shape.
type OpenSSLCAConfig struct {
	// OpenSSLPath is the path to the openssl binary. Defaults to
	// "openssl" (resolved via PATH); Validate resolves it via
	// exec.LookPath so a missing binary fails at startup, not on first
	// enrollment.
	OpenSSLPath string `json:"openssl_path,omitempty"`

	// ConfigFile is the operator's openssl.cnf.
	ConfigFile string `json:"config_file"`

	// ExtensionsSection names the -extensions section within ConfigFile
	// that fixes BasicConstraints/KeyUsage/ExtKeyUsage. Defaults to
	// "est_extensions".
	ExtensionsSection string `json:"extensions_section,omitempty"`
}

// CSRAttrsConfig is the plain-JSON shape of internal/csrattrs.Options — it
// deliberately doesn't import that package (config stays a leaf dependency;
// cmd/estd translates this into csrattrs.Options at startup).
type CSRAttrsConfig struct {
	ChallengePassword  bool                `json:"challenge_password"`
	KeyAlgorithm       *KeyAlgorithmConfig `json:"key_algorithm,omitempty"`
	RequiredExtensions []ExtensionConfig   `json:"required_extensions,omitempty"`
	ExtraOIDs          []string            `json:"extra_oids,omitempty"`
	Template           *TemplateConfig     `json:"template,omitempty"`
}

// KeyAlgorithmConfig requires a specific public key type. Set at most one
// of CurveOID or RSAModulusBits.
type KeyAlgorithmConfig struct {
	OID            string `json:"oid"`
	CurveOID       string `json:"curve_oid,omitempty"`
	RSAModulusBits int    `json:"rsa_modulus_bits,omitempty"`
}

// ExtensionConfig is a fully specified X.509 extension requirement (every
// value mandatory — used for the classic id-ExtensionReq attribute).
type ExtensionConfig struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical,omitempty"`
	ValueHex string `json:"value_hex"`
}

// TemplateConfig configures a CertificationRequestInfoTemplate attribute
// (RFC 9908 §3.4).
type TemplateConfig struct {
	Subject    []RDNConfig               `json:"subject,omitempty"`
	KeyType    *KeyAlgorithmConfig       `json:"key_type,omitempty"`
	Extensions []TemplateExtensionConfig `json:"extensions,omitempty"`
}

// RDNConfig is one subject RDN in a Template. A null (absent) value means
// the client fills it in; an explicit value (including "") dictates it.
type RDNConfig struct {
	OID   string  `json:"oid"`
	Value *string `json:"value,omitempty"`
}

// TemplateExtensionConfig is an extension requirement inside a
// TemplateConfig, whose value may be left null for the client to fill in.
type TemplateExtensionConfig struct {
	OID      string  `json:"oid"`
	Critical bool    `json:"critical,omitempty"`
	ValueHex *string `json:"value_hex,omitempty"`
}

// Load reads and parses a Config from a JSON file at path. It does not
// validate the result; call Validate separately.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &c, nil
}

// Validate checks that required fields are set and that referenced files
// exist, so misconfiguration is caught at startup rather than on first
// request. It also normalizes CABackend ("" becomes "local") and
// OpenSSLCA's defaults, so callers can rely on those being filled in
// after a successful Validate.
func (c *Config) Validate() error {
	if c.CABackend == "" {
		c.CABackend = "local"
	}
	if c.CABackend != "local" && c.CABackend != "openssl" {
		return fmt.Errorf("config: ca_backend must be \"local\" or \"openssl\", got %q", c.CABackend)
	}

	required := map[string]string{
		"listen_addr":      c.ListenAddr,
		"server_cert_file": c.ServerCertFile,
		"server_key_file":  c.ServerKeyFile,
		"ca_cert_file":     c.CACertFile,
		"store_dir":        c.StoreDir,
	}
	for field, value := range required {
		if value == "" {
			return fmt.Errorf("config: %s is required", field)
		}
	}
	if len(c.ClientCAFiles) == 0 {
		return fmt.Errorf("config: client_ca_files must contain at least one CA bundle")
	}
	if time.Duration(c.CertValidity) <= 0 {
		return fmt.Errorf("config: cert_validity must be a positive duration")
	}

	files := append([]string{c.ServerCertFile, c.ServerKeyFile, c.CACertFile}, c.ClientCAFiles...)

	switch c.CABackend {
	case "local":
		if c.CAKeyFile == "" {
			return fmt.Errorf("config: ca_key_file is required when ca_backend is \"local\"")
		}
		files = append(files, c.CAKeyFile)
	case "openssl":
		if c.OpenSSLCA == nil {
			return fmt.Errorf("config: openssl_ca is required when ca_backend is \"openssl\"")
		}
		if c.OpenSSLCA.ConfigFile == "" {
			return fmt.Errorf("config: openssl_ca.config_file is required")
		}
		if c.OpenSSLCA.OpenSSLPath == "" {
			c.OpenSSLCA.OpenSSLPath = "openssl"
		}
		if c.OpenSSLCA.ExtensionsSection == "" {
			c.OpenSSLCA.ExtensionsSection = "est_extensions"
		}
		if _, err := exec.LookPath(c.OpenSSLCA.OpenSSLPath); err != nil {
			return fmt.Errorf("config: openssl_ca.openssl_path: %w", err)
		}
		files = append(files, c.OpenSSLCA.ConfigFile)
	}

	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("config: %s: %w", f, err)
		}
	}
	return nil
}
