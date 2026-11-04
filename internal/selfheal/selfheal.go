// Package selfheal restores a sentinel file to its last known-good content after
// a malicious write, keeping the attacker's version as evidence. It snapshots a
// small set of high-value persistence/credential files at startup; on a
// malicious-write verdict (enforce mode with enforcement.self_heal only) it
// atomically rewrites the good content and quarantines what the attacker wrote.
// It only heals files it snapshotted and only on a verdict the engine judged
// malicious, so a legitimate edit — which scores low — is never reverted.
//
// Several sentinels (/home/*/.ssh/authorized_keys) live in directories an
// unprivileged user controls, and the agent runs as root, so every filesystem
// step here is symlink-safe: paths are resolved without following symlinks
// (openat2 RESOLVE_NO_SYMLINKS, or a component-by-component O_NOFOLLOW walk),
// all work after that is done through file descriptors, new files are created
// O_CREAT|O_EXCL|O_NOFOLLOW, and the parent directory must be owned by root or
// by the file's own owner and be the directory that was snapshotted. Only the
// snapshot side is picky about the file itself: whatever an attacker leaves at
// the path (a huge file, a symlink, a FIFO) is never followed or read through,
// but it IS replaced — the restore renames over it. See FORK.md.
package selfheal

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// maxSnapshot bounds how much of a sentinel the agent will hold in memory. The
// sentinel set is small text files; anything larger is not one of them.
const maxSnapshot = 4 << 20

// ErrUnsafe is wrapped by every refusal to touch a path that is not safe to
// operate on as root (a symlink, a non-regular file, a parent directory owned
// by someone other than root or the file's owner, or a swapped directory).
var ErrUnsafe = errors.New("unsafe path")

// Store holds the known-good snapshots and a quarantine directory for evidence.
type Store struct {
	mu         sync.Mutex
	good       map[string]snapshot
	inflight   map[string]bool // a heal is running for this path
	dirty      map[string]bool // another write arrived while it ran: heal again
	quarantine string
	// quotaBytes caps the evidence kept in the quarantine directory; the
	// oldest evidence files are pruned (and logged) past it.
	quotaBytes int64
}

// DefaultQuotaBytes caps the quarantine directory's evidence.
const DefaultQuotaBytes = 64 << 20

// snapshot is a file's known-good content plus the identity needed to restore
// it faithfully (owner, group, permission bits) and to notice that its parent
// directory was swapped out from under us (dev/inode of the parent).
type snapshot struct {
	content  []byte
	mode     os.FileMode
	uid, gid int
	label    []byte // security.selinux, when present (restored best effort)
	dirDev   uint64
	dirIno   uint64
}

// New returns a Store that quarantines attacker versions under quarantineDir.
// The directory is created 0700 if missing and must be a real directory (not a
// symlink) owned by the agent's effective uid; its permissions are tightened to
// 0700. Anything else is an error: evidence and staging files must not land
// somewhere another user can reach.
func New(quarantineDir string) (*Store, error) {
	if err := prepareQuarantine(quarantineDir); err != nil {
		return nil, err
	}
	return &Store{good: map[string]snapshot{}, inflight: map[string]bool{}, dirty: map[string]bool{},
		quarantine: quarantineDir, quotaBytes: DefaultQuotaBytes}, nil
}

// DefaultSentinels resolves the built-in high-value set that exists on this host:
// SSH authorized_keys (root and each home), cron, and the dynamic-loader preload.
// Paths are only candidates; Snapshot refuses any that is not safe to heal.
func DefaultSentinels() []string {
	var out []string
	add := func(p string) {
		if _, err := os.Lstat(p); err == nil {
			out = append(out, p)
		}
	}
	add("/root/.ssh/authorized_keys")
	add("/root/.ssh/authorized_keys2")
	homes, _ := filepath.Glob("/home/*/.ssh/authorized_keys")
	out = append(out, homes...)
	add("/etc/crontab")
	crond, _ := filepath.Glob("/etc/cron.d/*")
	out = append(out, crond...)
	add("/etc/ld.so.preload")
	return out
}

// Snapshot records the current content of a file as known-good. It refuses a
// path that is (or passes through) a symlink, is not a regular file, or whose
// parent directory is owned by neither root nor the file's owner.
func (s *Store) Snapshot(path string) error {
	snap, err := readSnapshot(filepath.Clean(path))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.good[filepath.Clean(path)] = snap
	s.mu.Unlock()
	return nil
}

// SnapshotAll snapshots every path and returns how many were captured. A path
// refused as unsafe is logged, so an operator can see it is not being watched.
func (s *Store) SnapshotAll(paths []string) int {
	n := 0
	for _, p := range paths {
		if err := s.Snapshot(p); err != nil {
			log.Printf("self-heal: not watching %q: %v", p, err)
			continue
		}
		n++
	}
	return n
}

// Watched reports whether a path has a known-good snapshot.
func (s *Store) Watched(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.good[filepath.Clean(path)]
	return ok
}

// Result is what one Heal did.
type Result struct {
	Healed   bool   // the known-good content was restored over a changed file
	Evidence string // where the tampered version was kept ("" if none or not kept)
}

// Heal saves the current (tampered) file to quarantine and atomically restores
// the known-good content, with the original owner, group and mode. A file
// whose content already matches the snapshot is left alone (Healed false).
// Only snapshotted files heal (others return a zero Result), and a heal that
// cannot be done without following a symlink or writing into a directory
// another user controls is refused with an error wrapping ErrUnsafe.
func (s *Store) Heal(path string) (Result, error) {
	path = filepath.Clean(path)
	s.mu.Lock()
	snap, ok := s.good[path]
	s.mu.Unlock()
	if !ok {
		return Result{}, nil
	}
	return heal(path, snap, s.quarantine, s.quotaBytes)
}

// Claim asks to heal path. It returns true if the caller now owns the heal
// and must run it (then call Finish until Finish returns false). If a heal of
// path is already running it returns false and marks the path dirty, so the
// running owner heals once more after it finishes: a write that lands after
// the running heal read the file is never lost, and a burst of writes still
// costs at most one extra heal.
func (s *Store) Claim(path string) bool {
	path = filepath.Clean(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[path] {
		s.dirty[path] = true
		return false
	}
	s.inflight[path] = true
	return true
}

// Finish is called by the owner after each heal of path. It returns true
// (keeping ownership, clearing the dirty bit) if another write was claimed
// meanwhile and the owner must heal again; otherwise it releases the path.
func (s *Store) Finish(path string) bool {
	path = filepath.Clean(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty[path] {
		delete(s.dirty, path)
		return true
	}
	delete(s.inflight, path)
	return false
}

func sanitize(p string) string {
	out := []rune(p)
	for i, r := range out {
		if r == '/' {
			out[i] = '_'
		}
	}
	return string(out)
}
