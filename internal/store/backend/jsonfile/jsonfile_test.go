package jsonfile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
)

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestDigestFollowsLoadAndSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	s := New(path)
	p := baseline.NewProfile()
	if err := s.Load(p); err != nil {
		t.Fatal(err)
	}
	if s.Digest() != NoBaseline {
		t.Errorf("digest with no file = %q, want %q", s.Digest(), NoBaseline)
	}
	p.Observe("k", 1)
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if s.Digest() != fileSHA(t, path) {
		t.Error("after Save the digest must be the file's sha256")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("baseline mode %v, want 0600", fi.Mode().Perm())
	}
	s2 := New(path)
	q := baseline.NewProfile()
	if err := s2.Load(q); err != nil {
		t.Fatal(err)
	}
	if s2.Digest() != s.Digest() || q.Count("k", 1) != 1 {
		t.Error("Load must report the same digest and restore the profile")
	}
	// The same learned state always serialises to the same bytes.
	if err := s2.Save(q); err != nil || s2.Digest() != s.Digest() {
		t.Errorf("re-save changed the digest (%v)", err)
	}
}

func TestLoadRefusesCorruptBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	os.WriteFile(path, []byte(`{"counts":`), 0o600)
	if err := New(path).Load(baseline.NewProfile()); err == nil {
		t.Fatal("a truncated baseline must fail the load")
	}
}

// Saves that overlap (a checkpoint and the shutdown save) never leave a
// partial file: each is a whole-file rename.
func TestConcurrentSavesLeaveAWholeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	s := New(path)
	p := baseline.NewProfile()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p.Observe("k", float64(i))
			if err := s.Save(p); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if err := New(path).Load(baseline.NewProfile()); err != nil {
		t.Fatalf("file after concurrent saves: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".baseline-*.tmp"))
	if len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("fsync of a directory: %v", err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing directory must fail the save")
	}
}

func TestSaveSyncsTheDirectoryAfterRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	prev := syncDir
	defer func() { syncDir = prev }()
	var synced []string
	syncDir = func(dir string) error {
		if _, err := os.Stat(path); err != nil {
			t.Error("directory synced before the rename")
		}
		synced = append(synced, dir)
		return prev(dir)
	}
	if err := New(path).Save(baseline.NewProfile()); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != filepath.Dir(path) {
		t.Errorf("synced %v, want [%s]", synced, filepath.Dir(path))
	}
	syncDir = func(string) error { return os.ErrPermission }
	if err := New(path).Save(baseline.NewProfile()); err == nil {
		t.Error("a failed directory sync must fail the save")
	}
}
