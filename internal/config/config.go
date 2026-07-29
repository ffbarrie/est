// Package config loads and validates the JSON configuration file for the
// EST server binary.
package config

import (
	"encoding/json"
	"fmt"
	"os"
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
	CAKeyFile      string   `json:"ca_key_file"`
	StoreDir       string   `json:"store_dir"`
	CertValidity   Duration `json:"cert_validity"`
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
// request.
func (c *Config) Validate() error {
	required := map[string]string{
		"listen_addr":      c.ListenAddr,
		"server_cert_file": c.ServerCertFile,
		"server_key_file":  c.ServerKeyFile,
		"ca_cert_file":     c.CACertFile,
		"ca_key_file":      c.CAKeyFile,
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

	files := append([]string{c.ServerCertFile, c.ServerKeyFile, c.CACertFile, c.CAKeyFile}, c.ClientCAFiles...)
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("config: %s: %w", f, err)
		}
	}
	return nil
}
