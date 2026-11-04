package decode

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/event/kind"
)

// record builds a raw ring-buffer sample matching struct phage_event. Every
// test goes through it, so it also guards the C<->Go layout contract: if the
// struct grows, Size changes and these tests fail until both sides agree.
type record struct {
	kind          uint32
	pid, ppid     uint32
	uid, newEUID  uint32
	loginUID      uint32
	flags         uint32
	capEff        uint64
	daddr         [16]byte
	dport, family uint16
	comm, pcomm   string
	path          string
}

func (rec record) bytes() []byte {
	var buf bytes.Buffer
	fields := []any{
		uint64(7),    // id
		uint64(1234), // ts_ns
		rec.kind,     // kind
		rec.pid,      // pid
		rec.ppid,     // ppid
		rec.uid,      // uid
		uint32(0),    // euid (unused by decode)
		rec.newEUID,  // new_euid
		rec.loginUID, // loginuid
		rec.flags,    // flags
		rec.capEff,   // cap_eff
		rec.daddr,    // daddr[16]
		rec.dport,    // dport
		rec.family,   // family
		uint32(0),    // _pad2
	}
	for _, f := range fields {
		binary.Write(&buf, binary.LittleEndian, f)
	}
	comm := [16]byte{}
	copy(comm[:], rec.comm)
	buf.Write(comm[:])
	pcomm := [16]byte{}
	copy(pcomm[:], rec.pcomm)
	buf.Write(pcomm[:])
	path := [160]byte{}
	copy(path[:], rec.path)
	buf.Write(path[:])
	return buf.Bytes()
}

// sample is a no-session setuid escalation (uid 999 -> root euid).
func sample() []byte {
	return record{
		kind: 2, pid: 4242, ppid: 99, uid: 999, newEUID: 0,
		loginUID: 0xFFFFFFFF, capEff: 0x1ff, comm: "rootshell", pcomm: "sh",
	}.bytes()
}

func TestEventDecodesFields(t *testing.T) {
	b := sample()
	if len(b) != Size {
		t.Fatalf("sample size = %d, want %d (layout drift vs events.bpf.h)", len(b), Size)
	}
	ev, err := Event(b)
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.PID != 4242 {
		t.Errorf("PID = %d, want 4242", ev.PID)
	}
	if ev.Comm != "rootshell" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "rootshell")
	}
	if ev.ParentComm != "sh" {
		t.Errorf("ParentComm = %q, want %q", ev.ParentComm, "sh")
	}
	if ev.KernelNs != 1234 {
		t.Errorf("KernelNs = %d, want ts_ns 1234 (the enrichment lag is measured from it)", ev.KernelNs)
	}
	if ev.Kind != kind.CredsChange {
		t.Errorf("Kind = %q, want %q", ev.Kind, kind.CredsChange)
	}
	if ev.Creds.UID != 999 || ev.Creds.EUID != 0 {
		t.Errorf("creds uid/euid = %d/%d, want 999/0", ev.Creds.UID, ev.Creds.EUID)
	}
	if !ev.RaisedToRoot() {
		t.Error("RaisedToRoot() = false, want true (uid 999 with euid 0)")
	}
	if ev.Session.Interactive {
		t.Error("Interactive = true, want false (loginuid unset)")
	}
	if ev.Session.LoginUID != -1 {
		t.Errorf("LoginUID = %d, want -1 (unset)", ev.Session.LoginUID)
	}
}

func TestConnectDecodesDestination(t *testing.T) {
	// 203.0.113.5:4444 — a classic reverse-shell callback. Address bytes are
	// stored network order (big-endian), as the kernel hands them to us.
	rec := record{
		kind: 4, pid: 5000, ppid: 4242, uid: 999,
		loginUID: 0xFFFFFFFF,
		daddr:    [16]byte{203, 0, 113, 5},
		dport:    4444,
		family:   afInet,
		comm:     "sh", pcomm: "node",
	}
	ev, err := Event(rec.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.Kind != kind.Connect {
		t.Fatalf("Kind = %q, want %q", ev.Kind, kind.Connect)
	}
	if ev.Net.DestIP != "203.0.113.5" {
		t.Errorf("DestIP = %q, want 203.0.113.5", ev.Net.DestIP)
	}
	if ev.Net.DestPort != 4444 {
		t.Errorf("DestPort = %d, want 4444", ev.Net.DestPort)
	}
}

func TestConnectDecodesIPv6(t *testing.T) {
	// 2001:db8::1 in network order.
	rec := record{
		kind: 4, pid: 5001, loginUID: 0xFFFFFFFF, dport: 443, family: afInet6,
		daddr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
		comm:  "curl",
	}
	ev, err := Event(rec.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.Net.DestIP != "2001:db8::1" {
		t.Errorf("DestIP = %q, want 2001:db8::1", ev.Net.DestIP)
	}
}

func TestFileWriteDecodesPathAndCategory(t *testing.T) {
	// A webshell dropped by a service-spawned shell into the web root.
	rec := record{
		kind: 5, pid: 6000, ppid: 5999, uid: 33, // www-data
		loginUID: 0xFFFFFFFF,
		comm:     "sh", pcomm: "php-fpm",
		path: "/var/www/html/uploads/shell.php",
	}
	ev, err := Event(rec.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.Kind != kind.FileWrite {
		t.Fatalf("Kind = %q, want %q", ev.Kind, kind.FileWrite)
	}
	if ev.File.Path != "/var/www/html/uploads/shell.php" {
		t.Errorf("File.Path = %q, want the webshell path", ev.File.Path)
	}
	if ev.File.Category != "web_php" {
		t.Errorf("File.Category = %q, want web_php", ev.File.Category)
	}
	if ev.Session.Interactive {
		t.Error("Interactive = true, want false (no login session behind a webshell drop)")
	}
}

func TestExecDecodesFilelessFlag(t *testing.T) {
	// An exec whose image has no on-disk link: fileless / memfd execution. The
	// attacker named the memfd "nginx" to blend in — the flag catches it anyway.
	rec := record{
		kind: 1, pid: 7000, ppid: 6999, loginUID: 0xFFFFFFFF,
		flags: 1, comm: "nginx", pcomm: "php-fpm",
	}
	ev, err := Event(rec.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.Kind != kind.Exec {
		t.Fatalf("Kind = %q, want %q", ev.Kind, kind.Exec)
	}
	if !ev.Fileless {
		t.Error("Fileless = false, want true (flags bit 0 set)")
	}

	// A normal exec (flags 0) must not be flagged fileless.
	normal := record{kind: 1, pid: 7001, loginUID: 0xFFFFFFFF, comm: "nginx", pcomm: "systemd"}
	ev2, _ := Event(normal.bytes())
	if ev2.Fileless {
		t.Error("Fileless = true for a normal exec, want false")
	}
}

func TestExecDecodesLdPreloadFlag(t *testing.T) {
	// flags bit 1 = a dynamic-linker hijack var in the environment.
	rec := record{kind: 1, pid: 7100, loginUID: 0xFFFFFFFF, flags: 2, comm: "sudo", pcomm: "bash"}
	ev, err := Event(rec.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if !ev.LdPreload {
		t.Error("LdPreload = false, want true (flags bit 1 set)")
	}
	if ev.Fileless {
		t.Error("Fileless = true, want false (only bit 1 set)")
	}
}

func TestEnableDecodesOp(t *testing.T) {
	// A service-spawned shell creates an unprivileged user namespace — the setup
	// for a kernel exploit. flags carries the op code (1 = userns).
	rec := record{
		kind: 6, pid: 8000, ppid: 7999, loginUID: 0xFFFFFFFF,
		flags: 1, comm: "bash", pcomm: "php-fpm",
	}
	ev, err := Event(rec.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.Kind != kind.Enable {
		t.Fatalf("Kind = %q, want %q", ev.Kind, kind.Enable)
	}
	if ev.EnableOp != "userns" {
		t.Errorf("EnableOp = %q, want userns", ev.EnableOp)
	}
	// op code 2 = bpf_load
	bpf := record{kind: 6, pid: 8001, loginUID: 0xFFFFFFFF, flags: 2, comm: "sh"}
	if ev2, _ := Event(bpf.bytes()); ev2.EnableOp != "bpf_load" {
		t.Errorf("EnableOp = %q, want bpf_load", ev2.EnableOp)
	}
}

func TestSelfDefenseDecodesOp(t *testing.T) {
	// subtype 1 (signal) with new_euid = 9 → SIGKILL aimed at the agent.
	kill := record{kind: 7, pid: 9000, loginUID: 0xFFFFFFFF, flags: 1, newEUID: 9, comm: "bash"}
	ev, err := Event(kill.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.Kind != kind.SelfDefense {
		t.Fatalf("Kind = %q, want %q", ev.Kind, kind.SelfDefense)
	}
	if ev.SelfDefOp != "SIGKILL" {
		t.Errorf("SelfDefOp = %q, want SIGKILL", ev.SelfDefOp)
	}
	// subtype 2 → ptrace.
	pt := record{kind: 7, pid: 9001, loginUID: 0xFFFFFFFF, flags: 2, comm: "gdb"}
	if ev2, _ := Event(pt.bytes()); ev2.SelfDefOp != "ptrace" {
		t.Errorf("SelfDefOp = %q, want ptrace", ev2.SelfDefOp)
	}
}

func TestHoneytokenDecodesPath(t *testing.T) {
	rec := record{kind: 8, pid: 9200, loginUID: 0xFFFFFFFF, comm: "bash", path: "/root/.aws/credentials"}
	ev, err := Event(rec.bytes())
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.Kind != kind.Honeytoken {
		t.Fatalf("Kind = %q, want %q", ev.Kind, kind.Honeytoken)
	}
	if ev.File.Path != "/root/.aws/credentials" {
		t.Errorf("File.Path = %q, want the decoy path", ev.File.Path)
	}
}

func TestEventRejectsShortSample(t *testing.T) {
	if _, err := Event([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on short sample")
	}
}
