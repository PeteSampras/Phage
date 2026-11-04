package honeytoken

import (
	"os"
	"path/filepath"
	"testing"
)

type env struct {
	root, state string
	decoys      []Decoy
}

func newEnv(t *testing.T) env {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return env{
		root:  root,
		state: filepath.Join(root, "state", "honeytokens.json"),
		decoys: []Decoy{
			{filepath.Join(root, "home", ".aws", "credentials"), "decoy-a\n"},
			{filepath.Join(root, "backups", ".pgpass"), "decoy-b\n"},
		},
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestSeedPlantsAndShutdownCleansUp(t *testing.T) {
	e := newEnv(t)
	os.MkdirAll(filepath.Join(e.root, "backups"), 0o755) // pre-existing dir: must survive
	m := New(e.state, e.decoys)
	planted, err := m.Seed()
	if err != nil || len(planted) != 2 {
		t.Fatalf("Seed = %v, %v", planted, err)
	}
	if len(Inodes(planted)) != 2 || planted[0].Ino == 0 {
		t.Fatalf("inodes not recorded: %+v", planted)
	}
	if !exists(e.state) {
		t.Fatal("no state record written")
	}
	m.Shutdown(planted)
	for _, d := range e.decoys {
		if exists(d.Path) {
			t.Errorf("decoy %s left behind", d.Path)
		}
	}
	if exists(filepath.Join(e.root, "home")) {
		t.Error("directories the agent created must be removed")
	}
	if !exists(filepath.Join(e.root, "backups")) {
		t.Error("a directory that existed before must be kept")
	}
	if exists(e.state) {
		t.Error("state record should be removed on shutdown")
	}
}

func TestSeedNeverTouchesARealFile(t *testing.T) {
	e := newEnv(t)
	real := e.decoys[1].Path
	os.MkdirAll(filepath.Dir(real), 0o755)
	os.WriteFile(real, []byte("REAL CREDENTIAL\n"), 0o600)
	planted, err := New(e.state, e.decoys).Seed()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range planted {
		if p.Path == real {
			t.Fatal("a real file was taken as a decoy")
		}
	}
	Remove(planted)
	if b, _ := os.ReadFile(real); string(b) != "REAL CREDENTIAL\n" {
		t.Fatalf("real file modified: %q", b)
	}
}

func TestSeedReadoptsAfterCrash(t *testing.T) {
	e := newEnv(t)
	first, err := New(e.state, e.decoys).Seed()
	if err != nil || len(first) != 2 {
		t.Fatal(err)
	}
	// Crash: no Shutdown. The next start must re-adopt, not skip as "real".
	second, err := New(e.state, e.decoys).Seed()
	if err != nil || len(second) != 2 {
		t.Fatalf("after a crash: planted %d, err %v; want the 2 stale decoys re-adopted", len(second), err)
	}
	for i := range second {
		if !second[i].Adopted || second[i].Ino != first[i].Ino {
			t.Errorf("decoy %s not re-adopted: %+v", second[i].Path, second[i])
		}
	}
	New(e.state, e.decoys).Shutdown(second)
	if exists(filepath.Join(e.root, "home")) {
		t.Error("re-adopted decoys must still clean up the directories created for them")
	}
}

func TestRemoveOnlyTheInodeThatWasPlanted(t *testing.T) {
	e := newEnv(t)
	planted, err := New(e.state, e.decoys).Seed()
	if err != nil {
		t.Fatal(err)
	}
	// Someone replaces a decoy with their own file at the same path.
	p := planted[0].Path
	os.Remove(p)
	os.WriteFile(p, []byte("not ours\n"), 0o600)
	Remove(planted)
	if b, err := os.ReadFile(p); err != nil || string(b) != "not ours\n" {
		t.Fatalf("a file that is not the planted inode was removed or changed: %q %v", b, err)
	}
}

func TestSeedDoesNotFollowSymlink(t *testing.T) {
	e := newEnv(t)
	victim := filepath.Join(e.root, "victim")
	os.WriteFile(victim, []byte("v\n"), 0o600)
	os.MkdirAll(filepath.Dir(e.decoys[0].Path), 0o700)
	os.Symlink(victim, e.decoys[0].Path) // dangling or not, never written through
	planted, _ := New(e.state, e.decoys).Seed()
	Remove(planted)
	if b, _ := os.ReadFile(victim); string(b) != "v\n" {
		t.Fatalf("decoy written through a symlink: %q", b)
	}
}
