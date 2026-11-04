package app

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/AzozzALFiras/Phage/internal/enrich/process"
	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// fileID identifies an inode independently of any path.
type fileID struct{ dev, ino uint64 }

// procView is the agent's read of /proc, behind an interface so the identity
// rules can be tested without real processes.
type procView interface {
	// ExeID stats /proc/<pid>/exe (the inode actually executing, even if it
	// has been unlinked) and reads its link text.
	ExeID(pid int32) (id fileID, nlink uint64, link string, err error)
	PPID(pid int32) (int32, error)
	UID(pid int32) (int, error) // real uid
	// RootFileID stats path as the process sees it: resolved inside
	// /proc/<pid>/root, following no symlinks.
	RootFileID(pid int32, path string) (fileID, error)
}

// hostProc reads the real /proc.
type hostProc struct{}

func (hostProc) ExeID(pid int32) (fileID, uint64, string, error) {
	p := fmt.Sprintf("/proc/%d/exe", pid)
	fi, err := os.Stat(p)
	if err != nil {
		return fileID{}, 0, "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, 0, "", fmt.Errorf("no stat for %s", p)
	}
	link, _ := os.Readlink(p)
	return fileID{uint64(st.Dev), uint64(st.Ino)}, uint64(st.Nlink), link, nil
}

func (hostProc) PPID(pid int32) (int32, error) {
	st, err := process.ReadStat(pid)
	return st.PPID, err
}

func (hostProc) UID(pid int32) (int, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return strconv.Atoi(fields[0])
			}
		}
	}
	return -1, fmt.Errorf("no Uid line for pid %d", pid)
}

// sshdExes are the OpenSSH server binaries (the listener, and the per-session
// sshd-session / sshd-auth helpers of OpenSSH >= 9.8) at their usual install
// paths. Writing to them needs root.
var sshdExes = []string{
	"/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd",
	"/usr/local/sbin/sshd", "/usr/local/bin/sshd",
	"/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session",
	"/usr/lib/ssh/sshd-session", "/usr/libexec/sshd-session",
	"/usr/lib/openssh/sshd-auth", "/usr/libexec/openssh/sshd-auth",
	"/usr/lib/ssh/sshd-auth", "/usr/libexec/sshd-auth",
}

// sshdIdentity recognises the host's sshd by inode, not by name or path text:
// the dev+ino of the installed sshd binaries is resolved at startup (and again
// on a miss, so a package upgrade is picked up), and a process is sshd only if
// /proc/<pid>/exe is one of those inodes.
type sshdIdentity struct {
	mu    sync.Mutex
	known map[fileID]bool
	paths []string
	stat  func(path string) (fileID, error)
}

func newSSHDIdentity() *sshdIdentity {
	s := &sshdIdentity{paths: sshdExes, stat: statID}
	s.refresh()
	return s
}

func statID(path string) (fileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, fmt.Errorf("no stat for %s", path)
	}
	return fileID{uint64(st.Dev), uint64(st.Ino)}, nil
}

func (s *sshdIdentity) refresh() {
	known := map[fileID]bool{}
	for _, p := range s.paths {
		if id, err := s.stat(p); err == nil {
			known[id] = true
		}
	}
	s.mu.Lock()
	s.known = known
	s.mu.Unlock()
}

func (s *sshdIdentity) has(id fileID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.known[id]
}

func (s *sshdIdentity) listed(path string) bool {
	for _, p := range s.paths {
		if p == path {
			return true
		}
	}
	return false
}

// isSSHDExe reports whether pid is executing a host sshd binary. A running sshd
// whose binary a package upgrade has since replaced still counts: its exe is an
// unlinked inode (nlink 0) whose link text is a listed path + " (deleted)" —
// a path only root could have executed from.
func (s *sshdIdentity) isSSHDExe(v procView, pid int32) bool {
	if pid <= 0 || s == nil || v == nil {
		return false
	}
	id, nlink, link, err := v.ExeID(pid)
	if err != nil {
		return false
	}
	if s.has(id) {
		return true
	}
	s.refresh()
	if s.has(id) {
		return true
	}
	if p, ok := strings.CutSuffix(link, " (deleted)"); ok && nlink == 0 && s.listed(p) {
		return true
	}
	return false
}

// verified reports whether pid is a genuine sshd: it runs a host sshd binary,
// and so does every ancestor up to one whose parent is pid 1 and whose real uid
// is 0 (the listener started by init). A user-installed copy of sshd, or one
// started by anything but init, does not qualify.
func (s *sshdIdentity) verified(v procView, pid int32) bool {
	cur := pid
	for depth := 0; depth < 8; depth++ {
		if !s.isSSHDExe(v, cur) {
			return false
		}
		pp, err := v.PPID(cur)
		if err != nil || pp <= 0 {
			return false
		}
		if pp == 1 {
			uid, err := v.UID(cur)
			return err == nil && uid == 0
		}
		cur = pp
	}
	return false
}

// criticalComms is a hard safety allowlist: processes Phage must never contain,
// because doing so could lock an operator out of the machine or wedge the
// system. This is a deliberate hardcoded guardrail (not a learned signal) — it
// exists because enforce mode once froze SSH logins and locked the box out.
//
// sshd and the agent itself are NOT here: sshd is recognised by inode and
// ancestry (sshdIdentity) and the agent by its pid.
var criticalComms = map[string]bool{
	"systemd": true, "init": true, "login": true,
	"agetty": true, "getty": true, "systemd-logind": true,
	"dbus-daemon": true, "systemd-journal": true,
}

// containmentSafe is the HARD never-lock-out guardrail on any containment
// (isolate or freeze): it refuses to contain (a) anything backed by an
// interactive login session — never lock out the admin path — (b) the agent,
// (c) sshd and its direct children, and (d) the other control-plane processes.
// Proportionality lives in the response matrix; this stays a pure safety gate.
//
// A process merely NAMED sshd* (or parented by one) that fails the identity
// check is still never contained — a false "not sshd" here is a lockout — but
// that is logged loudly as UNVERIFIED so the evasion is visible.
func containmentSafe(ev model.Event, self int32, v procView, sshd *sshdIdentity) (bool, string) {
	if ev.Session.Interactive {
		return false, "interactive login session"
	}
	if ev.PID == self || (ev.PPID != 0 && ev.PPID == self) {
		return false, "the agent itself"
	}
	if sshd.verified(v, ev.PID) || sshd.verified(v, ev.PPID) {
		return false, "control-plane process (verified sshd)"
	}
	if strings.HasPrefix(ev.Comm, "sshd") || strings.HasPrefix(ev.ParentComm, "sshd") {
		exe := ""
		if v != nil {
			_, _, exe, _ = v.ExeID(ev.PID)
		}
		log.Printf("WARNING containment skipped for UNVERIFIED sshd-named process pid=%d comm=%q parent=%q exe=%q: not the host sshd by inode/ancestry — possible evasion",
			ev.PID, ev.Comm, ev.ParentComm, exe)
		return false, "unverified sshd-named process (never contained; logged)"
	}
	if criticalComms[ev.Comm] || criticalComms[ev.ParentComm] {
		return false, "control-plane process"
	}
	return true, ""
}

// writerSeesHostFile decides whether a malicious write reported at path may
// trigger a heal of the HOST file at path. The event's path was resolved in
// the writer's view of the filesystem, which can differ from the host's (a
// container, or `unshare -m`). A namespace comparison is the wrong test: a new
// mount namespace that has not remounted anything still writes the host inode.
// So: resolve path inside the writer's root (/proc/<pid>/root, no symlinks)
// and heal only if that is the host's inode. If the writer's view cannot be
// read (it exited, or the path no longer resolves there), heal anyway and let
// the content decide — Heal compares the HOST file with its own snapshot and
// does nothing if it is unchanged, which is exactly the case of a container
// writing its private copy. Only a definite "different file" skips the heal.
func writerSeesHostFile(v procView, pid int32, path string) (bool, string) {
	host, err := lstatID(path)
	if err != nil {
		return true, "" // host file missing or unreadable: Heal restores or refuses
	}
	if v == nil {
		return true, ""
	}
	w, err := v.RootFileID(pid, path)
	if err != nil {
		return true, "" // writer gone / view unreadable: the host file's content decides
	}
	if w != host {
		return false, fmt.Sprintf("writer pid %d resolves %s to a different file (dev %d ino %d) than the host's (dev %d ino %d) — its own namespace's copy",
			pid, path, w.dev, w.ino, host.dev, host.ino)
	}
	return true, ""
}

func lstatID(path string) (fileID, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, fmt.Errorf("no stat for %s", path)
	}
	return fileID{uint64(st.Dev), uint64(st.Ino)}, nil
}
