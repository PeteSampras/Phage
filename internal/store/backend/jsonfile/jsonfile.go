// Package jsonfile persists a baseline as a single JSON snapshot on disk. It is
// the lightest backend that survives restarts — no daemon, no dependency — which
// suits Phage's "stay small" goal. Writes are atomic (temp file + rename) so a
// crash mid-save never corrupts the learned baseline.
package jsonfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
)

// Store is a file-backed Repository. It remembers the sha256 of the bytes it
// last loaded or saved, so the daemon can name the exact baseline it runs on.
type Store struct {
	path string

	mu     sync.Mutex
	digest string
}

// NoBaseline is the digest reported when no baseline file exists yet.
const NoBaseline = "none"

// Digest returns the hex sha256 of the baseline file as last loaded or saved,
// or NoBaseline before a file exists.
func (s *Store) Digest() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.digest == "" {
		return NoBaseline
	}
	return s.digest
}

func (s *Store) setDigest(b []byte) {
	sum := sha256.Sum256(b)
	s.mu.Lock()
	s.digest = hex.EncodeToString(sum[:])
	s.mu.Unlock()
}

// New returns a Store backed by the file at path.
func New(path string) *Store { return &Store{path: path} }

// Load reads the snapshot into p. A missing file is not an error.
func (s *Store) Load(p *baseline.Profile) error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // fresh host: start empty
	}
	if err != nil {
		return fmt.Errorf("read baseline %q: %w", s.path, err)
	}
	var snap baseline.Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("parse baseline %q: %w", s.path, err)
	}
	p.Import(snap)
	s.setDigest(b)
	return nil
}

// Save writes p atomically: marshal, write a temp file in the same directory,
// fsync, then rename over the target. A crash at any point leaves either the
// previous file or the new one, never a partial file. The learn-mode
// checkpoint and the save at shutdown both come through here.
func (s *Store) Save(p *baseline.Profile) error {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create state dir: %w", err)
		}
	}
	b, err := json.Marshal(p.Export())
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	s.setDigest(b)
	return nil
}
