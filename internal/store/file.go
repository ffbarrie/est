package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// FileStore is a Store implementation backed by the local filesystem:
//
//	<dir>/csrs/<serial-hex>.der
//	<dir>/certs/<serial-hex>.der
//	<dir>/certs/<serial-hex>.json  (Metadata)
//
// serial-hex is the zero-padded, lowercase hex encoding of the serial
// number, giving unique, fixed-width, filesystem-sortable names. Writes go
// to a temp file followed by an atomic rename, so a crash never leaves a
// partially-written cert or CSR file in place.
type FileStore struct {
	dir string
}

// NewFileStore returns a FileStore rooted at dir. dir is created if it does
// not already exist.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", dir, err)
	}
	return &FileStore{dir: dir}, nil
}

func serialHex(serial *big.Int) string {
	return fmt.Sprintf("%040x", serial)
}

func (s *FileStore) csrPath(serial *big.Int) string {
	return filepath.Join(s.dir, "csrs", serialHex(serial)+".der")
}

func (s *FileStore) certPath(serial *big.Int) string {
	return filepath.Join(s.dir, "certs", serialHex(serial)+".der")
}

func (s *FileStore) certMetaPath(serial *big.Int) string {
	return filepath.Join(s.dir, "certs", serialHex(serial)+".json")
}

// writeFileAtomic writes data to path via a temp file in the same
// directory followed by a rename, so concurrent readers never observe a
// partially-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}
	return nil
}

// PutCSR implements Store, writing csrDER to <dir>/csrs/<serial-hex>.der.
func (s *FileStore) PutCSR(ctx context.Context, serial *big.Int, csrDER []byte, meta Metadata) error {
	return writeFileAtomic(s.csrPath(serial), csrDER, 0o640)
}

// PutCertificate implements Store, writing certDER and meta to
// <dir>/certs/<serial-hex>.der and .json respectively.
func (s *FileStore) PutCertificate(ctx context.Context, serial *big.Int, certDER []byte, meta Metadata) error {
	if err := writeFileAtomic(s.certPath(serial), certDER, 0o640); err != nil {
		return err
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	return writeFileAtomic(s.certMetaPath(serial), metaJSON, 0o640)
}

// GetCertificate implements Store, reading back a certificate previously
// written by PutCertificate.
func (s *FileStore) GetCertificate(ctx context.Context, serial *big.Int) (*x509.Certificate, error) {
	der, err := os.ReadFile(s.certPath(serial))
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

var _ Store = (*FileStore)(nil)
