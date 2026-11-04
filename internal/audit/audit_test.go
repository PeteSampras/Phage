package audit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenCreates0600(t *testing.T) {
	old := syscall.Umask(0) // so only Open's own mode can make this pass
	defer syscall.Umask(old)
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("created with %v, want 0600", fi.Mode().Perm())
	}
}

func TestOpenTightensExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	os.WriteFile(p, nil, 0o644)
	os.Chmod(p, 0o644)
	w, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("existing trail left at %v, want tightened to 0600", fi.Mode().Perm())
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "shadow")
	os.WriteFile(victim, []byte("root:x\n"), 0o600)
	link := filepath.Join(dir, "audit.jsonl")
	os.Symlink(victim, link)
	if w, err := Open(link); err == nil {
		w.Record(Entry{Kind: KindStartup})
		w.Close()
		t.Fatal("Open followed a symlink at the audit path")
	}
	if b, _ := os.ReadFile(victim); string(b) != "root:x\n" {
		t.Fatalf("symlink target modified: %q", b)
	}
	dangling := filepath.Join(dir, "dangling.jsonl")
	os.Symlink(filepath.Join(dir, "created-through-link"), dangling)
	if _, err := Open(dangling); err == nil {
		t.Error("Open accepted a dangling symlink")
	}
	if _, err := os.Lstat(filepath.Join(dir, "created-through-link")); err == nil {
		t.Error("Open created a file through a dangling symlink")
	}
}

func TestOpenRefusesFIFOWithoutHanging(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		w, err := Open(p)
		if err == nil {
			w.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open accepted a FIFO as the audit trail")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Open hung on a FIFO")
	}
}

// A device node at the audit path must be refused by the regular-file check
// (it would otherwise "work": writes to a /dev/null clone vanish silently).
func TestOpenRefusesDeviceNode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := syscall.Mknod(p, syscall.S_IFCHR|0o600, int(1<<8|3)); err != nil { // like /dev/null (1,3)
		t.Skipf("cannot mknod a character device here (needs root): %v", err)
	}
	w, err := Open(p)
	if err == nil {
		w.Close()
		t.Fatal("Open accepted a character device as the audit trail")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Skipf("device refused before the regular-file check (e.g. a nodev mount): %v", err)
	}
}

func TestOpenRefusesHardLinkAndForeignOwner(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("x"), 0o600)
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Link(victim, link); err != nil {
		t.Skip(err)
	}
	if _, err := Open(link); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Errorf("a hard-linked trail must be refused, got %v", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("chown needs root")
	}
	other := filepath.Join(dir, "other.jsonl")
	os.WriteFile(other, nil, 0o600)
	if err := os.Chown(other, 4242, 4242); err != nil {
		t.Skip(err)
	}
	if _, err := Open(other); err == nil || !strings.Contains(err.Error(), "owned by uid 4242") {
		t.Errorf("a trail owned by another uid must be refused, got %v", err)
	}
}
