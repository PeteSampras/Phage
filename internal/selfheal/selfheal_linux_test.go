//go:build linux

package selfheal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

		res, err := f.store.Heal(f.target, 0)
		q := res.Evidence
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
				if strings.Contains(e.Name(), "phage-heal") {
					t.Errorf("leftover staging file %s/%s", dir, e.Name())
				}
			}
		}
	})
}

func TestHealUnchangedIsNoop(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	if res, err := f.store.Heal(f.target, 0); err != nil || res.Healed || res.Evidence != "" {
		t.Fatalf("Heal on an unchanged file = (%+v, %v), want a zero Result", res, err)
	}
}

func TestHealRestoresDeletedFile(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	os.Remove(f.target)
	if _, err := f.store.Heal(f.target, 0); err != nil {
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

		if _, err := f.store.Heal(f.target, 0); err != nil {
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

// An attacker who swaps the sentinel for a symlink must not make root write
// through it — but the swap must not defeat the heal either: the link itself is
// replaced by the known-good file and its target recorded as evidence.
func TestHealReplacesTargetSwappedForSymlink(t *testing.T) {
	bothResolvers(t, func(t *testing.T) {
		f := newFixture(t)
		mustSnapshot(t, f)
		victim := filepath.Join(f.root, "shadow")
		writeFile(t, victim, "root:secret\n", 0o600)
		os.Remove(f.target)
		if err := os.Symlink(victim, f.target); err != nil {
			t.Fatal(err)
		}

		res, err := f.store.Heal(f.target, 0)
		q := res.Evidence
		if err != nil {
			t.Fatalf("Heal: %v", err)
		}
		if got := readFile(t, victim); got != "root:secret\n" {
			t.Fatalf("victim modified through the symlink: %q", got)
		}
		fi, _ := os.Lstat(f.target)
		if !fi.Mode().IsRegular() || readFile(t, f.target) != "good\n" {
			t.Errorf("target not restored as a regular file: mode %v", fi.Mode())
		}
		if q == "" || !strings.Contains(readFile(t, q), victim) {
			t.Errorf("evidence %q should record the symlink target", q)
		}
	})
}

// Growing the file past the snapshot bound used to make the read fail and the
// heal give up. The restore no longer depends on reading the tampered file.
func TestHealRestoresOversizedTarget(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	big := strings.Repeat("A", maxSnapshot+1024)
	writeFile(t, f.target, big, 0o640)
	res, err := f.store.Heal(f.target, 0)
	q := res.Evidence
	if err != nil {
		t.Fatalf("Heal: %v", err)
	}
	if readFile(t, f.target) != "good\n" {
		t.Error("oversized target not restored")
	}
	ev := readFile(t, q)
	if len(ev) > maxEvidence+200 || !strings.Contains(ev, "truncated") {
		t.Errorf("evidence should be truncated with a note (len %d)", len(ev))
	}
}

func TestClaimDirtyBitReruns(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	if !f.store.Claim(f.target, 0) {
		t.Fatal("first claim must succeed")
	}
	// Writes arriving while the heal runs: not a second owner, but a rerun.
	if f.store.Claim(f.target, 0) || f.store.Claim(f.target, 0) {
		t.Fatal("a claim while a heal is running must not hand out a second owner")
	}
	if again, _ := f.store.Finish(f.target); !again {
		t.Fatal("Finish must ask the owner to heal again after a claim arrived mid-heal")
	}
	if again, _ := f.store.Finish(f.target); again {
		t.Fatal("a burst collapses to one rerun; the second Finish must release")
	}
	if !f.store.Claim(f.target, 0) {
		t.Fatal("claim after release must succeed")
	}
}

// The rerun is made for the LEAST-privileged writer seen meanwhile: a
// non-root writer's event must not be healed with root's authority because a
// root event was also pending.
func TestClaimRerunKeepsLeastPrivilegedWriter(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	for _, c := range []struct {
		name    string
		pending []int
		want    int
	}{
		{"root then user", []int{0, 4242}, 4242},
		{"user then root", []int{4242, 0}, 4242},
		{"only root", []int{0, 0}, 0},
		{"two different users", []int{4242, 4343}, -1},
	} {
		if !f.store.Claim(f.target, 0) {
			t.Fatalf("%s: setup claim", c.name)
		}
		for _, uid := range c.pending {
			f.store.Claim(f.target, uid)
		}
		again, uid := f.store.Finish(f.target)
		if !again || uid != c.want {
			t.Errorf("%s: Finish = (%v, %d), want (true, %d)", c.name, again, uid, c.want)
		}
		if again, _ := f.store.Finish(f.target); again {
			t.Fatalf("%s: release", c.name)
		}
	}
}

func TestQuarantineQuotaPrunesOldest(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	f.store.quotaBytes = 6000 // 3000 per pool
	var kept []string
	for i := 0; i < 5; i++ {
		writeFile(t, f.target, strings.Repeat("x", 1000)+string(rune('a'+i)), 0o640)
		res, err := f.store.Heal(f.target, 0)
		q := res.Evidence
		if err != nil {
			t.Fatal(err)
		}
		kept = append(kept, q)
	}
	ents, _ := os.ReadDir(f.quarantine)
	var total int64
	for _, e := range ents {
		fi, _ := e.Info()
		total += fi.Size()
	}
	if total > 3000 {
		t.Errorf("quarantine holds %d bytes, over the 3000-byte quota", total)
	}
	if _, err := os.Stat(kept[0]); err == nil {
		t.Error("the oldest evidence should have been pruned")
	}
	if _, err := os.Stat(kept[4]); err != nil {
		t.Error("the newest evidence must be kept")
	}
}

// Pruning goes by age (mtime), not by name, and leftover .stage-* files from
// an older version are removed rather than counted as evidence.
func TestPruneByMtimeAndCleanStaging(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	files := []struct {
		name string
		age  time.Duration
	}{
		{"r-a-newest", 1 * time.Minute}, // name sorts first, but it is the newest
		{"r-m-middle", 2 * time.Hour},
		{"r-z-oldest", 5 * time.Hour}, // name sorts last, but it is the oldest
	}
	for _, e := range files {
		p := filepath.Join(f.quarantine, e.name)
		writeFile(t, p, strings.Repeat("x", 1000), 0o600)
		ts := now.Add(-e.age)
		os.Chtimes(p, ts, ts)
	}
	stage := filepath.Join(f.quarantine, ".stage-authorized_keys.0123")
	writeFile(t, stage, strings.Repeat("s", 5000), 0o600)

	qfd, err := openNoSymlinks(f.quarantine, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(qfd)
	pruneQuarantine(f.quarantine, qfd, 2000, "", rootPool)

	if _, err := os.Stat(stage); err == nil {
		t.Error("leftover .stage-* file must be removed")
	}
	if _, err := os.Stat(filepath.Join(f.quarantine, "r-z-oldest")); err == nil {
		t.Error("the oldest evidence by mtime must be pruned first")
	}
	for _, keep := range []string{"r-a-newest", "r-m-middle"} {
		if _, err := os.Stat(filepath.Join(f.quarantine, keep)); err != nil {
			t.Errorf("%s pruned; only enough of the oldest to meet the quota should go (staging must not count)", keep)
		}
	}
}

// The restored copy must be staged in the TARGET's directory (same fs, the
// directory's default SELinux context), never in the quarantine dir.
func TestHealStagesInTargetDirectory(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	writeFile(t, f.target, "evil\n", 0o640)
	var stagedIn []string
	stageHook = func(dirfd int, name string) {
		dir, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", dirfd))
		stagedIn = append(stagedIn, dir)
	}
	defer func() { stageHook = nil }()
	if _, err := f.store.Heal(f.target, 0); err != nil {
		t.Fatal(err)
	}
	if len(stagedIn) != 1 || stagedIn[0] != f.sshDir {
		t.Fatalf("staged in %v, want exactly the target directory %s", stagedIn, f.sshDir)
	}
}

// The restored copy is staged beside the target (same directory), never in the
// quarantine dir, so it takes the directory's default SELinux context; a label
// recorded at snapshot time is re-applied best effort.
func TestHealCopiesSELinuxLabelWhenPossible(t *testing.T) {
	f := newFixture(t)
	label := []byte("system_u:object_r:ssh_home_t:s0")
	if err := unix.Setxattr(f.target, selinuxXattr, label, 0); err != nil {
		t.Skipf("cannot set %s here (%v): no SELinux/security xattr support", selinuxXattr, err)
	}
	mustSnapshot(t, f)
	writeFile(t, f.target, "evil\n", 0o640)
	if _, err := f.store.Heal(f.target, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := unix.Getxattr(f.target, selinuxXattr, buf)
	if err != nil || string(buf[:n]) != string(label) {
		t.Errorf("label after heal = %q (%v), want %q", buf[:n], err, label)
	}
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

		_, err := f.store.Heal(f.target, 0)
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
	if _, err := f.store.Heal(f.target, 0); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal into a swapped directory: err = %v, want ErrUnsafe", err)
	}
}

func TestHealReplacesNonRegularTarget(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	os.Remove(f.target)
	if err := syscall.Mkfifo(f.target, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if _, err := f.store.Heal(f.target, 0); err != nil {
		t.Fatalf("Heal of a FIFO: %v", err)
	}
	if fi, _ := os.Lstat(f.target); !fi.Mode().IsRegular() {
		t.Errorf("FIFO not replaced: %v", fi.Mode())
	}
}

func TestHealRefusesDirectoryTarget(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	os.Remove(f.target)
	os.Mkdir(f.target, 0o700)
	if _, err := f.store.Heal(f.target, 0); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal over a directory: err = %v, want ErrUnsafe", err)
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
	writeFile(t, f.target, "evil\n", 0o666) // tampered in place: owner unchanged, mode loosened
	os.Chown(f.target, 4242, 0)             // group changed

	if _, err := f.store.Heal(f.target, 0); err != nil {
		t.Fatalf("Heal: %v", err)
	}
	var st syscall.Stat_t
	syscall.Lstat(f.target, &st)
	if st.Uid != 4242 || st.Gid != 4243 || st.Mode&0o777 != 0o640 {
		t.Errorf("owner/mode = %d:%d %o, want original 4242:4243 640", st.Uid, st.Gid, st.Mode&0o777)
	}
}

// The heal must never hand a file back to an old owner: if the owner changed
// since the snapshot (an admin made alice's file root-owned), refuse.
func TestHealRefusesOwnerChange(t *testing.T) {
	requireRoot(t)
	f := newFixture(t)
	os.Chown(f.sshDir, 4242, 4242)
	os.Chown(f.target, 4242, 4242)
	mustSnapshot(t, f)
	writeFile(t, f.target, "admin-revoked-alice-key\n", 0o600)
	os.Chown(f.target, 0, 0)
	if _, err := f.store.Heal(f.target, 0); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal after an owner change: err = %v, want ErrUnsafe", err)
	}
	var st syscall.Stat_t
	syscall.Lstat(f.target, &st)
	if b, _ := os.ReadFile(f.target); string(b) != "admin-revoked-alice-key\n" || st.Uid != 0 {
		t.Fatalf("file changed by a refused heal: %q uid %d", b, st.Uid)
	}
}

func TestCurrentOwner(t *testing.T) {
	requireRoot(t)
	f := newFixture(t)
	mustSnapshot(t, f)
	os.Chown(f.target, 4242, 4242)
	if uid, err := f.store.CurrentOwner(f.target); err != nil || uid != 4242 {
		t.Errorf("CurrentOwner = %d, %v; want the owner now (4242), not at snapshot", uid, err)
	}
	// An absent file has no owner: no directory-owner fallback.
	os.Remove(f.target)
	os.Chown(f.sshDir, 4343, 4343)
	if _, err := f.store.CurrentOwner(f.target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent file: err = %v, want os.ErrNotExist", err)
	}
}

// Sentinels in a group- or world-writable directory (sticky or not) are never
// watched: another user can replace or remove them between any check and the
// restore.
func TestSnapshotRefusesSharedDirectory(t *testing.T) {
	for _, m := range []os.FileMode{0o777, 0o770, 0o777 | os.ModeSticky, 0o770 | os.ModeSticky} {
		f := newFixture(t)
		if err := os.Chmod(f.sshDir, m); err != nil {
			t.Fatal(err)
		}
		if fi, _ := os.Stat(f.sshDir); fi.Mode()&(os.ModePerm|os.ModeSticky) != m {
			t.Fatalf("setup: dir mode %v, want %v", fi.Mode(), m)
		}
		if err := f.store.Snapshot(f.target); !errors.Is(err, ErrUnsafe) {
			t.Errorf("dir mode %v: Snapshot err = %v, want ErrUnsafe", m, err)
		}
	}
}

// ...and a directory made shared after the snapshot is re-checked at heal time.
func TestHealRefusesDirectoryMadeSharedLater(t *testing.T) {
	f := newFixture(t)
	mustSnapshot(t, f)
	writeFile(t, f.target, "evil\n", 0o640)
	os.Chmod(f.sshDir, 0o777|os.ModeSticky)
	if fi, _ := os.Stat(f.sshDir); fi.Mode()&os.ModeSticky == 0 {
		t.Fatal("setup: sticky bit not set")
	}
	if _, err := f.store.Heal(f.target, 0); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal in a now world-writable dir: err = %v, want ErrUnsafe", err)
	}
}

// The writer's uid is re-checked under the verified fd: a non-root writer may
// only cause a restore of a file that exists and is owned by it (== snapshot
// owner); an absent file is recreated only for a root writer.
func TestHealWriterUIDRules(t *testing.T) {
	requireRoot(t)
	// root-owned sentinel
	f := newFixture(t)
	mustSnapshot(t, f)
	writeFile(t, f.target, "evil\n", 0o640)
	if _, err := f.store.Heal(f.target, 4242); !errors.Is(err, ErrUnsafe) {
		t.Errorf("uid 4242 healing a root-owned file: err = %v, want ErrUnsafe", err)
	}
	os.Remove(f.target)
	if _, err := f.store.Heal(f.target, 4242); !errors.Is(err, ErrUnsafe) || exists(f.target) {
		t.Errorf("uid 4242, absent file: err = %v, recreated=%v; want refusal", err, exists(f.target))
	}
	if r, err := f.store.Heal(f.target, 0); err != nil || !r.Healed {
		t.Errorf("root writer, absent file: %+v %v; want it restored", r, err)
	}

	// user-owned sentinel in the user's own directory
	g := newFixture(t)
	os.Chown(g.sshDir, 4242, 4242)
	os.Chown(g.target, 4242, 4242)
	mustSnapshot(t, g)
	writeFile(t, g.target, "evil\n", 0o640)
	if r, err := g.store.Heal(g.target, 4242); err != nil || !r.Healed {
		t.Errorf("owner healing own file: %+v %v", r, err)
	}
	writeFile(t, g.target, "evil\n", 0o640)
	if _, err := g.store.Heal(g.target, 4343); !errors.Is(err, ErrUnsafe) {
		t.Errorf("a different user healing it: err = %v, want ErrUnsafe", err)
	}
	os.Remove(g.target)
	if _, err := g.store.Heal(g.target, 4242); !errors.Is(err, ErrUnsafe) || exists(g.target) {
		t.Errorf("owner, absent file: err = %v; a non-root writer must not make root recreate it", err)
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

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
	if _, err := f.store.Heal(f.target, 0); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Heal under a third user's dir: err = %v, want ErrUnsafe", err)
	}
}

// N3: a user who can rewrite their own sentinel at will must not be able to
// evict the evidence of an attack on a root-owned sentinel by generating
// evidence of their own.
func TestUserEvidenceNeverEvictsRootEvidence(t *testing.T) {
	requireRoot(t) // needs a second owner for the user-owned sentinel
	f := newFixture(t)
	f.store.quotaBytes = 4000 // 2000 per pool
	mustSnapshot(t, f)        // root-owned
	writeFile(t, f.target, strings.Repeat("R", 1500), 0o640)
	rootRes, err := f.store.Heal(f.target, 0)
	if err != nil || rootRes.Evidence == "" {
		t.Fatalf("root heal: %+v %v", rootRes, err)
	}

	udir := filepath.Join(f.root, "home", "alice", ".ssh")
	os.MkdirAll(udir, 0o700)
	os.Chown(udir, 4242, 4242)
	ukeys := filepath.Join(udir, "authorized_keys")
	writeFile(t, ukeys, "alice\n", 0o600)
	os.Chown(ukeys, 4242, 4242)
	if err := f.store.Snapshot(ukeys); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		writeFile(t, ukeys, strings.Repeat("u", 900)+string(rune('a'+i)), 0o600)
		os.Chown(ukeys, 4242, 4242)
		if _, err := f.store.Heal(ukeys, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(rootRes.Evidence); err != nil {
		t.Fatal("evidence of the root-owned sentinel was evicted by user-owned evidence")
	}
	var userBytes int64
	ents, _ := os.ReadDir(f.quarantine)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), userPool) {
			fi, _ := e.Info()
			userBytes += fi.Size()
		}
	}
	if userBytes > 2000 {
		t.Errorf("user pool holds %d bytes, over its 2000-byte half of the quota", userBytes)
	}
}
