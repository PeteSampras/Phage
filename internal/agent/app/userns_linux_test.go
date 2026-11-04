//go:build linux

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/response/action"
)

// spawnUserNS runs script as a writer in a new user + mount namespace
// (`unshare -Urm`, private propagation), waits until it has finished its setup
// (it must end by touching $READY), and returns its pid. It skips the test with
// the reason when user namespaces are unavailable here.
func spawnUserNS(t *testing.T, script string) int32 {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare(1) not installed: cannot create a user+mount namespace writer")
	}
	if out, err := exec.Command("unshare", "-Urm", "--propagation", "private", "true").CombinedOutput(); err != nil {
		t.Skipf("user+mount namespaces unavailable here (unshare -Urm: %v %s)", err, strings.TrimSpace(string(out)))
	}
	ready := filepath.Join(t.TempDir(), "ready")
	c := exec.Command("unshare", "-Urm", "--propagation", "private", "sh", "-c", script+" && touch "+ready+" && exec sleep 30")
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Start(); err != nil {
		t.Skipf("unshare: %v", err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			return int32(c.Process.Pid)
		}
	}
	t.Fatal("namespace writer did not finish its setup")
	return 0
}

func sentinel(t *testing.T) string {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(root, "home", ".ssh", "authorized_keys")
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte("good\n"), 0o600)
	return p
}

// A user+mount namespace that remounts nothing writes the HOST inode: a root
// writer (or the file's current owner) heals; an unprivileged non-owner never
// does, whatever its view resolves to.
func TestRealWriterInNewMountNSSeesHostFile(t *testing.T) {
	host := sentinel(t) // root-owned
	pid := spawnUserNS(t, "true")
	if ok, why := writerSeesHostFile(hostProc{}, pid, host, 0, 0); !ok {
		t.Fatalf("a root writer in unshare -Urm without remount writes the host inode and must heal: %s", why)
	}
	if ok, _ := writerSeesHostFile(hostProc{}, pid, host, 4242, 0); ok {
		t.Fatal("uid 4242 must not heal a root-owned file, even though its view is the host inode")
	}
}

// A writer that put a private tmpfs over the directory and wrote its own copy
// sees a DIFFERENT file: no heal, whatever its uid. This fails if the path is
// resolved in the host's root instead of /proc/<pid>/root, or without
// RESOLVE_IN_ROOT (an absolute path then ignores the writer's root fd).
func TestRealWriterPrivateCopyIsNotTheHostFile(t *testing.T) {
	host := sentinel(t)
	pid := spawnUserNS(t, "mount -t tmpfs t "+filepath.Dir(host)+" && echo private > "+host)
	if ok, _ := writerSeesHostFile(hostProc{}, pid, host, 0, 0); ok {
		t.Fatal("a writer's private tmpfs copy was taken for the host file")
	}
}

// B1: an unprivileged user writes a private copy in its own namespace, deletes
// it (so its view no longer resolves), and stays alive. The host file was
// legitimately edited by an admin after the snapshot; the agent must NOT
// revert that edit (e.g. reinstate a revoked key).
func TestPrivateNSWriteDoesNotRevertAdminEdit(t *testing.T) {
	f := newHealFixture(t)
	f.a.proc = hostProc{}
	os.WriteFile(f.target, []byte("admin-revoked-the-bad-key\n"), 0o600) // legit edit, scored low earlier
	dir := filepath.Dir(f.target)
	pid := spawnUserNS(t, "mount -t tmpfs t "+dir+" && echo x > "+f.target+" && rm "+f.target)
	f.a.respond(model.Event{Kind: kind.FileWrite, PID: pid, PPID: 1, Comm: "sh",
		Creds: model.Credentials{UID: 4242}, // an unprivileged user in the init namespace
		File:  model.FileWrite{Path: f.target}}, verdict.Verdict{Score: 0.95}, action.Notify)
	f.a.healWG.Wait()
	if b, _ := os.ReadFile(f.target); string(b) != "admin-revoked-the-bad-key\n" {
		t.Fatalf("the admin's edit was reverted by a private-namespace write: %q", b)
	}
	resp := recordsOfKind(t, f.audit, "response")
	if len(resp) != 1 || !strings.Contains(resp[0].Reason, "self-heal skipped") {
		t.Errorf("the skip should be recorded in the response reason: %+v", resp)
	}
}
