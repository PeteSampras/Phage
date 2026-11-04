//go:build linux

package selfheal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Every test runs twice: once through openat2(RESOLVE_NO_SYMLINKS) and once
// through the O_NOFOLLOW component walk used where openat2 is unavailable.
func bothResolvers(t *testing.T, fn func(t *testing.T)) {
	for _, walk := range []bool{false, true} {
		name := "openat2"
		if walk {
			name = "walk"
		}
		t.Run(name, func(t *testing.T) {
			prev := forceWalk
			forceWalk = walk
			defer func() { forceWalk = prev }()
			fn(t)
		})
	}
}

type fixture struct {
	root, sshDir, target, quarantine string
	store                            *Store
}

// newFixture lays out <root>/home/u/.ssh/authorized_keys (0640, "good") and a
// quarantine dir, all under a symlink-free temp root.
func newFixture(t *testing.T) fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{root: root}
	f.sshDir = filepath.Join(root, "home", "u", ".ssh")
	if err := os.MkdirAll(f.sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.target = filepath.Join(f.sshDir, "authorized_keys")
	writeFile(t, f.target, "good\n", 0o640)
	f.quarantine = filepath.Join(root, "quarantine")
	f.store, err = New(f.quarantine)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func writeFile(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // defeat the test's umask
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustSnapshot(t *testing.T, f fixture) {
	t.Helper()
	if err := f.store.Snapshot(f.target); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
}

func TestHealRestoresContentAndMode(t *testing.T) {
	bothResolvers(t, func(t *testing.T) {
		f := newFixture(t)
		mustSnapshot(t, f)
		writeFile(t, f.target, "evil\n", 0o666)

		q, err := f.store.Heal(f.target)
		if err != nil {
			t.Fatalf("Heal: %v", err)
		}
		if got := readFile(t, f.target); got != "good\n" {
			t.Errorf("content = %q, want restored %q", got, "good\n")
		}
		fi, _ := os.Lstat(f.target)
		if fi.Mode() != 0o640 {
			t.Errorf("mode = %v, want original 0640", fi.Mode())
		}
		if q == "" || readFile(t, q) != "evil\n" {
			t.Errorf("quarantine %q should hold the attacker's version", q)
		}
		// Nothing left behind: no staging file next to the target or in quarantine.
		for _, dir := range []string{f.sshDir, f.quarantine} {
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				if strings.Contains(e.Name(), "stage") || strings.Contains(e.Name(), "phage-heal") {
					t.Errorf("leftover staging file %s/%s", dir, e.Name())
				}
			}
		}
	})
}

func TestHealUnchangedIsNoop(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	if q, err := f.store.Heal(f.target); err != nil || q != "" {
		t.Fatalf("Heal on an unchanged file = (%q, %v), want (\"\", nil)", q, err)
	}
}

func TestHealRestoresDeletedFile(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	os.Remove(f.target)
	if _, err := f.store.Heal(f.target); err != nil {
		t.Fatalf("Heal: %v", err)
	}
	if got := readFile(t, f.target); got != "good\n" {
		t.Errorf("content = %q, want %q", got, "good\n")
	}
}

// The upstream bug: root wrote path+".phage-heal" with os.WriteFile, which
// follows a symlink a local user planted there, truncating any file on the box.
func TestHealIgnoresPlantedTempSymlink(t *testing.T) {
	bothResolvers(t, func(t *testing.T) {
		f := newFixture(t)
		mustSnapshot(t, f)
		victim := filepath.Join(f.root, "shadow")
		writeFile(t, victim, "root:secret\n", 0o600)
		if err := os.Symlink(victim, f.target+".phage-heal"); err != nil {
			t.Fatal(err)
		}
		writeFile(t, f.target, "evil\n", 0o640)

		if _, err := f.store.Heal(f.target); err != nil {
			t.Fatalf("Heal: %v", err)
		}
		if got := readFile(t, victim); got != "root:secret\n" {
			t.Fatalf("victim file was written through a planted symlink: %q", got)
		}
		if got := readFile(t, f.target); got != "good\n" {
			t.Errorf("target not restored: %q", got)
		}
	})
}

func TestHealRefusesTargetSwappedForSymlink(t *testing.T) {
	bothResolvers(t, func(t *testing.T) {
		f := newFixture(t)
		mustSnapshot(t, f)
		victim := filepath.Join(f.root, "shadow")
		writeFile(t, victim, "root:secret\n", 0o600)
		os.Remove(f.target)
		if err := os.Symlink(victim, f.target); err != nil {
			t.Fatal(err)
		}

		_, err := f.store.Heal(f.target)
		if !errors.Is(err, ErrUnsafe) {
			t.Fatalf("Heal through a symlinked target: err = %v, want ErrUnsafe", err)
		}
		if got := readFile(t, victim); got != "root:secret\n" {
			t.Fatalf("victim modified: %q", got)
		}
		if fi, _ := os.Lstat(f.target); fi.Mode()&os.ModeSymlink == 0 {
			t.Error("the symlink was replaced; a refused heal must not touch the path")
		}
	})
}

func TestHealRefusesParentSwappedForSymlink(t *testing.T) {
	bothResolvers(t, func(t *testing.T) {
		f := newFixture(t)
		mustSnapshot(t, f)
		// The user moves ~/.ssh aside and points ~/.ssh at a root-owned dir.
		other := filepath.Join(f.root, "etc")
		os.MkdirAll(other, 0o755)
		victim := filepath.Join(other, "authorized_keys")
		writeFile(t, victim, "root:secret\n", 0o600)
		if err := os.Rename(f.sshDir, f.sshDir+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, f.sshDir); err != nil {
			t.Fatal(err)
		}

		_, err := f.store.Heal(f.target)
		if !errors.Is(err, ErrUnsafe) {
			t.Fatalf("Heal through a symlinked parent: err = %v, want ErrUnsafe", err)
		}
		if got := readFile(t, victim); got != "root:secret\n" {
			t.Fatalf("file behind the symlinked parent was modified: %q", got)
		}
	})
}

func TestHealRefusesReplacedParentDir(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	if err := os.Rename(f.sshDir, f.sshDir+".old"); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(f.sshDir, 0o700)
	if _, err := f.store.Heal(f.target); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal into a swapped directory: err = %v, want ErrUnsafe", err)
	}
}

func TestHealRefusesNonRegularTarget(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	os.Remove(f.target)
	if err := syscall.Mkfifo(f.target, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if _, err := f.store.Heal(f.target); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal of a FIFO: err = %v, want ErrUnsafe", err)
	}
}

func TestSnapshotRefusesSymlinks(t *testing.T) {
	bothResolvers(t, func(t *testing.T) {
		f := newFixture(t)
		link := filepath.Join(f.sshDir, "authorized_keys2")
		if err := os.Symlink(f.target, link); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Snapshot(link); !errors.Is(err, ErrUnsafe) {
			t.Errorf("Snapshot of a symlink: err = %v, want ErrUnsafe", err)
		}
		// A symlink in an intermediate component is refused too.
		linkDir := filepath.Join(f.root, "home", "v")
		if err := os.Symlink(filepath.Join(f.root, "home", "u"), linkDir); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Snapshot(filepath.Join(linkDir, ".ssh", "authorized_keys")); !errors.Is(err, ErrUnsafe) {
			t.Errorf("Snapshot through a symlinked directory: err = %v, want ErrUnsafe", err)
		}
		if f.store.Watched(link) {
			t.Error("a refused path must not be watched")
		}
	})
}

func TestNewRefusesSymlinkedQuarantine(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(root, "q")
	os.Symlink(real, link)
	if _, err := New(link); err == nil {
		t.Fatal("New accepted a symlinked quarantine dir")
	}
}

func TestNewTightensQuarantineMode(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	q := filepath.Join(root, "q")
	os.Mkdir(q, 0o755)
	os.Chmod(q, 0o755)
	if _, err := New(q); err != nil {
		t.Fatalf("New: %v", err)
	}
	if fi, _ := os.Stat(q); fi.Mode().Perm() != 0o700 {
		t.Errorf("quarantine mode = %v, want 0700", fi.Mode().Perm())
	}
}

// --- cases that need root to set up a second owner -------------------------

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the test chowns files/dirs to a second uid to model another user")
	}
}

func TestHealPreservesOwner(t *testing.T) {
	requireRoot(t)
	f := newFixture(t)
	// The file belongs to uid 4242 in a directory it owns (a home .ssh).
	os.Chown(f.sshDir, 4242, 4242)
	os.Chown(f.target, 4242, 4243)
	mustSnapshot(t, f)
	writeFile(t, f.target, "evil\n", 0o640)
	os.Chown(f.target, 0, 0)

	if _, err := f.store.Heal(f.target); err != nil {
		t.Fatalf("Heal: %v", err)
	}
	var st syscall.Stat_t
	syscall.Lstat(f.target, &st)
	if st.Uid != 4242 || st.Gid != 4243 {
		t.Errorf("owner = %d:%d, want original 4242:4243", st.Uid, st.Gid)
	}
}

func TestSnapshotRefusesParentOwnedByThirdUser(t *testing.T) {
	requireRoot(t)
	f := newFixture(t)
	// Root's file in a directory uid 4242 controls: 4242 could race the heal.
	os.Chown(f.sshDir, 4242, 4242)
	if err := f.store.Snapshot(f.target); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Snapshot under a third user's dir: err = %v, want ErrUnsafe", err)
	}
}

func TestHealRefusesParentChownedAfterSnapshot(t *testing.T) {
	requireRoot(t)
	f := newFixture(t)
	mustSnapshot(t, f)
	os.Chown(f.sshDir, 4242, 4242)
	writeFile(t, f.target, "evil\n", 0o640)
	if _, err := f.store.Heal(f.target); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal under a third user's dir: err = %v, want ErrUnsafe", err)
	}
}
