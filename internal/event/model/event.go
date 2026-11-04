// Package model defines the enriched, domain-level event that flows through
// Phage's analysis pipeline. It is deliberately decoupled from the raw eBPF
// wire format (decoded in internal/sensor/decode) so the kernel side and the
// reasoning side can evolve independently.
package model

import (
	"strings"
	"time"

	"github.com/AzozzALFiras/Phage/internal/event/kind"
)

// ProcRef is one node in a process lineage chain.
type ProcRef struct {
	PID  int32
	Comm string
	Exe  string
}

// Credentials captures the privilege state relevant to escalation analysis.
type Credentials struct {
	UID, EUID, SUID int32
	GID, EGID, SGID int32
	CapEffective    uint64
}

// NetConn describes the destination of an outbound connection. It is set only
// on Connect events and is the backbone of egress detection: a reverse shell or
// C2 beacon is a process reaching out to somewhere it has no business going.
type NetConn struct {
	DestIP   string // destination address, text form; empty on non-connect events
	DestPort uint16 // destination port, host order
	Family   uint16 // AF_INET (2) or AF_INET6 (10)
}

// FileWrite describes a write-open of a persistence- or credential-relevant
// file. It is set only on FileWrite events and is the backbone of persistence
// detection: a program modifying an artifact it has never touched on this host —
// a webshell dropped into the web root, a key appended to authorized_keys, a
// cron job planted — is exactly the signal Phage learns to recognise.
type FileWrite struct {
	Path     string // resolved path, text form; empty on non-file events
	Category string // coarse artifact class (see CategorizePath); the learned key
}

// CategorizePath maps a resolved path to a coarse persistence/credential class.
// The class — not the raw filename — is what the baseline learns, so "this
// program writes this *kind* of artifact" stays stable across names (otherwise
// every freshly-named webshell would look novel). The classes are a scoping
// vocabulary, never a verdict: whether a program writing a class is malicious is
// decided by the learned baseline, not here.
func CategorizePath(p string) string {
	switch {
	case strings.HasSuffix(p, "authorized_keys"), strings.HasSuffix(p, "authorized_keys2"):
		return "ssh_authorized_keys"
	case strings.Contains(p, "/.ssh/"):
		return "ssh_dir"
	case strings.HasPrefix(p, "/etc/cron"), strings.HasPrefix(p, "/var/spool/cron"), strings.Contains(p, "/cron."):
		return "cron"
	case strings.HasPrefix(p, "/etc/ld.so."):
		return "ld_preload"
	case strings.HasPrefix(p, "/etc/passwd"):
		return "passwd"
	case strings.HasPrefix(p, "/etc/shadow"):
		return "shadow"
	case strings.HasPrefix(p, "/etc/sudoers"):
		return "sudoers"
	case strings.HasSuffix(p, ".service"), strings.HasSuffix(p, ".timer"), strings.HasSuffix(p, ".socket"):
		return "systemd_unit"
	case strings.HasSuffix(p, ".php"), strings.HasSuffix(p, ".phtml"),
		strings.HasSuffix(p, ".php5"), strings.HasSuffix(p, ".php7"), strings.HasSuffix(p, ".phar"):
		return "web_php"
	case strings.HasSuffix(p, ".jsp"), strings.HasSuffix(p, ".jspx"), strings.HasSuffix(p, ".war"):
		return "web_jsp"
	case strings.HasSuffix(p, ".asp"), strings.HasSuffix(p, ".aspx"):
		return "web_asp"
	case strings.HasPrefix(p, "/etc/init.d"), strings.HasPrefix(p, "/etc/rc"):
		return "init_script"
	case strings.Contains(p, "/profile.d/"), strings.HasPrefix(p, "/etc/profile"),
		strings.HasSuffix(p, "/.bashrc"), strings.HasSuffix(p, "/.bash_profile"), strings.HasSuffix(p, "/.profile"):
		return "shell_rc"
	default:
		return "sensitive_write"
	}
}

// Session links an event back to its authenticated origin, if any. This is the
// backbone of provenance-based detection: a root transition with no interactive
// session behind it is exactly the signal Phage cares about.
type Session struct {
	ID          int32  // kernel session id (sid)
	TTY         string // controlling terminal; empty means none
	Interactive bool   // backed by a real login / ssh session
	LoginUID    int32  // audit login uid; -1 when there is no login session
	RemoteAddr  string // set when the session traces back to sshd
}

// Event is the unit of analysis: an enriched, self-contained description of one
// privilege-relevant thing that happened.
type Event struct {
	ID         uint64
	Time       time.Time
	KernelNs   uint64 // the kernel's capture time (bpf_ktime_get_ns: CLOCK_MONOTONIC); 0 when unknown
	Kind       kind.Kind
	PID        int32
	PPID       int32
	Comm       string
	ParentComm string // immediate parent's comm, captured in-kernel (race-free)
	Fileless   bool   // exec from an anonymous in-memory image (memfd / unlinked binary); set on Exec events
	LdPreload  bool   // exec carried a dynamic-linker hijack var (LD_PRELOAD/LD_AUDIT/GLIBC_TUNABLES); set on Exec events
	EnableOp   string // high-risk kernel-enabling op name (userns/bpf_load/io_uring/userfaultfd); set on Enable events
	SelfDefOp  string // tamper sub-type against the agent: a signal name (e.g. SIGKILL) or "ptrace"; set on SelfDefense events
	Exe        string
	Args       []string
	CWD        string
	Creds      Credentials
	Session    Session
	Net        NetConn   // destination of an outbound connection; set on Connect events
	File       FileWrite // the persistence/credential file a write-open targeted; set on FileWrite events
	Lineage    []ProcRef // ancestry; index 0 is the immediate parent
	Container  string    // container / cgroup id; empty on a bare host
}

// GainedRoot reports whether this event represents the process holding root
// privileges. It is a measurement, not a verdict.
func (e Event) GainedRoot() bool {
	return e.Creds.UID == 0 || e.Creds.EUID == 0
}

// RaisedToRoot reports whether an unprivileged real uid is running with a root
// effective uid — the classic shape of a setuid-style escalation. Unlike a
// root daemon (uid 0, euid 0), this is privilege being *raised*, not held.
func (e Event) RaisedToRoot() bool {
	return e.Creds.UID != 0 && e.Creds.EUID == 0
}
