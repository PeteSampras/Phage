//go:build linux

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
	"github.com/AzozzALFiras/Phage/internal/selfheal"
)

// Regression tests for self-heal attacks found in review, run with REAL
// unprivileged writers: setpriv to uid 4242, then unshare -Urm (a user + mount
// namespace in which that user may mount a tmpfs over the sentinel's
// directory). They need root (for setpriv) and unprivileged user namespaces.

const attackerUID = 4242

// openDir returns a temp dir every uid can traverse (the attacker must reach
// the sentinel directory's parent; the directory itself may be 0700).
func openDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for p := d; p != "/" && p != os.TempDir(); p = filepath.Dir(p) {
		if strings.HasPrefix(p, os.TempDir()+"/") {
			os.Chmod(p, 0o755)
		}
	}
	return d
}

func requireAttacker(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: setpriv must switch to an unprivileged uid to model the attacker")
	}
	for _, tool := range []string{"setpriv", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s(1) not installed", tool)
		}
	}
	u := strconv.Itoa(attackerUID)
	if out, err := exec.Command("setpriv", "--reuid", u, "--regid", u, "--clear-groups",
		"unshare", "-Urm", "true").CombinedOutput(); err != nil {
		t.Skipf("unprivileged user namespaces unavailable (%v %s)", err, strings.TrimSpace(string(out)))
	}
}

// spawnAttacker runs script as uid 4242 in unshare -Urm and returns its pid
// once setup is done (the process stays alive).
func spawnAttacker(t *testing.T, script string) int32 {
	t.Helper()
	readyDir := openDir(t)
	os.Chmod(readyDir, 0o777)
	ready := filepath.Join(readyDir, "ready")
	u := strconv.Itoa(attackerUID)
	c := exec.Command("setpriv", "--reuid", u, "--regid", u, "--clear-groups",
		"unshare", "-Urm", "--propagation", "private", "sh", "-c", script+" && touch "+ready+" && exec sleep 30")
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	for d := time.Now().Add(5 * time.Second); time.Now().Before(d); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			return int32(c.Process.Pid)
		}
	}
	t.Fatal("attacker setup did not finish")
	return 0
}

type attackFx struct {
	a      *App
	target string
	audit  string
}

// newAttackFx: <open dir>/home/.ssh/authorized_keys owned by fileUID (the .ssh
// dir too, 0700), snapshotted, self-heal armed, real /proc.
func newAttackFx(t *testing.T, fileUID int) attackFx {
	t.Helper()
	home := filepath.Join(openDir(t), "home")
	os.Mkdir(home, 0o755)
	dir := filepath.Join(home, ".ssh")
	os.Mkdir(dir, 0o700)
	os.Chown(dir, fileUID, fileUID)
	target := filepath.Join(dir, "authorized_keys")
	os.WriteFile(target, []byte("good\n"), 0o600)
	os.Chown(target, fileUID, fileUID)
	h, err := selfheal.New(filepath.Join(t.TempDir(), "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Snapshot(target); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Mode, cfg.Enforcement = mode.Enforce, config.Enforcement{SelfHeal: true}
	a, path := appWithAudit(t, cfg, Meta{})
	a.healer, a.proc, a.sshd, a.freezer = h, hostProc{}, testSSHD(), &fakeFreezer{}
	a.contained, a.recentLimit = map[int32]*contState{}, 100
	a.healGate, a.healDelay = writerSeesHostFile, func() {}
	return attackFx{a, target, path}
}

// fire delivers the write-open event the sensor would report for pid, with the
// writer's real init-namespace uid as the kernel records it.
func (f attackFx) fire(pid int32, uid int) {
	f.a.respond(model.Event{Kind: kind.FileWrite, PID: pid, PPID: 1, Comm: "sh",
		Creds: model.Credentials{UID: int32(uid)},
		File:  model.FileWrite{Path: f.target}}, verdict.Verdict{Score: 0.95}, action.Notify)
	f.a.healWG.Wait()
}

func (f attackFx) mustStill(t *testing.T, want string, why string) {
	t.Helper()
	if b, _ := os.ReadFile(f.target); string(b) != want {
		t.Fatalf("%s: host file is %q, want %q", why, b, want)
	}
}

// A1: private copy in a tmpfs over the directory, removed, writer alive.
func TestAttackPrivateCopyRemoved(t *testing.T) {
	requireAttacker(t)
	f := newAttackFx(t, 0)
	os.WriteFile(f.target, []byte("admin-revoked-the-bad-key\n"), 0o600)
	dir := filepath.Dir(f.target)
	pid := spawnAttacker(t, "mount -t tmpfs t "+dir+" && echo x > "+f.target+" && rm "+f.target)
	f.fire(pid, attackerUID)
	f.mustStill(t, "admin-revoked-the-bad-key\n", "A1: unprivileged private write reverted the admin's edit")
}

// A1b: same, writer exited before the event is handled.
func TestAttackPrivateCopyWriterExited(t *testing.T) {
	requireAttacker(t)
	f := newAttackFx(t, 0)
	os.WriteFile(f.target, []byte("admin-revoked-the-bad-key\n"), 0o600)
	dir := filepath.Dir(f.target)
	u := strconv.Itoa(attackerUID)
	c := exec.Command("setpriv", "--reuid", u, "--regid", u, "--clear-groups",
		"unshare", "-Urm", "--propagation", "private", "sh", "-c", "mount -t tmpfs t "+dir+" && echo x > "+f.target)
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	f.fire(int32(c.Process.Pid), attackerUID)
	f.mustStill(t, "admin-revoked-the-bad-key\n", "A1b: exited unprivileged writer reverted the admin's edit")
}

// A2: write a private copy (the event), then UNMOUNT the tmpfs, so the
// writer's view resolves to the host inode again by the time the event is
// handled. The inode match alone must not authorise the heal.
func TestAttackWriteThenUnmount(t *testing.T) {
	requireAttacker(t)
	f := newAttackFx(t, 0)
	os.WriteFile(f.target, []byte("admin-revoked-the-bad-key\n"), 0o600)
	dir := filepath.Dir(f.target)
	pid := spawnAttacker(t, "mount -t tmpfs t "+dir+" && echo x > "+f.target+" && umount "+dir)
	if id, err := (hostProc{}).RootFileID(pid, f.target); err == nil {
		if host, _ := lstatID(f.target); id != host {
			t.Fatalf("setup: the attacker's view should resolve to the host inode after umount")
		}
	}
	f.fire(pid, attackerUID)
	f.mustStill(t, "admin-revoked-the-bad-key\n", "A2: unprivileged uid reverted a root-owned sentinel")
	resp := recordsOfKind(t, f.audit, "response")
	if len(resp) != 1 || !strings.Contains(resp[0].Reason, "neither root nor the current owner") {
		t.Errorf("skip reason not recorded: %+v", resp)
	}
}

// A3: alice owned the file at snapshot; the admin later revoked her key and
// made the file root-owned. Alice is not the CURRENT owner and must not get it
// reverted (and handed back to her).
func TestAttackSnapshotOwnerIsNotCurrentOwner(t *testing.T) {
	requireAttacker(t)
	f := newAttackFx(t, attackerUID)
	os.WriteFile(f.target, []byte("admin-revoked-alice-key\n"), 0o600)
	os.Chown(f.target, 0, 0)
	dir := filepath.Dir(f.target)
	pid := spawnAttacker(t, "mount -t tmpfs t "+dir+" && echo x > "+f.target+" && rm "+f.target)
	f.fire(pid, attackerUID)
	f.mustStill(t, "admin-revoked-alice-key\n", "A3: the snapshot owner reverted a file she no longer owns")
	resp := recordsOfKind(t, f.audit, "response")
	if len(resp) != 1 || !strings.Contains(resp[0].Reason, "neither root nor the current owner") {
		t.Errorf("A3: skip reason not recorded: %+v", resp)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(f.target, &st); err != nil || st.Uid != 0 {
		t.Errorf("A3: ownership handed back to uid %d (%v)", st.Uid, err)
	}
}

// A3 as root: even a writer that passes the gate cannot make Heal restore an
// owner that differs from the current one; the refusal is audited.
func TestHealRefusesOwnerChangeAudited(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the sentinel must be owned by a second uid")
	}
	f := newAttackFx(t, attackerUID)
	os.WriteFile(f.target, []byte("admin-revoked-alice-key\n"), 0o600)
	os.Chown(f.target, 0, 0)
	f.fire(800, 0) // fake pid with no /proc view: the root writer passes the gate
	f.mustStill(t, "admin-revoked-alice-key\n", "Heal restored an old owner's snapshot")
	recs := recordsOfKind(t, f.audit, "self_heal")
	if len(recs) != 1 || !strings.HasPrefix(recs[0].Outcome, "failed:") || !strings.Contains(recs[0].Outcome, "owner") {
		t.Fatalf("self_heal records = %+v, want one failed:<owner changed>", recs)
	}
}

// Neither alert mode nor enforce without self_heal may even consult the gate.
func TestHealGateNotConsultedUnlessArmed(t *testing.T) {
	for _, m := range []mode.Mode{mode.Alert, mode.Enforce} {
		f := newHealFixture(t)
		f.a.cfg.Mode, f.a.cfg.Enforcement = m, config.Enforcement{}
		f.a.healGate = func(procView, int32, string, int, int) (bool, string) {
			t.Fatalf("mode %s without self_heal consulted the heal gate", m)
			return false, ""
		}
		f.write(t, 800, action.Notify)
		f.a.healWG.Wait()
		if b, _ := os.ReadFile(f.target); string(b) != "evil\n" {
			t.Fatalf("mode %s without self_heal healed: %q", m, b)
		}
	}
}

// asAttacker runs a shell command as uid 4242 in the init namespaces (a plain
// local user acting on the host filesystem).
func asAttacker(t *testing.T, sh string) {
	t.Helper()
	u := strconv.Itoa(attackerUID)
	if out, err := exec.Command("setpriv", "--reuid", u, "--regid", u, "--clear-groups", "sh", "-c", sh).CombinedOutput(); err != nil {
		t.Fatalf("attacker %q: %v %s", sh, err, out)
	}
}

// sharedDirFx: a root-owned sentinel in a root-owned directory that is 0755
// at snapshot time (so it is watched) and is then opened up to dirMode — the
// heal-time state the attacker exploits. During the heal delay the attacker
// deletes the file it just planted.
func sharedDirFx(t *testing.T, dirMode os.FileMode) attackFx {
	t.Helper()
	requireAttacker(t)
	dir := filepath.Join(openDir(t), "shared")
	os.Mkdir(dir, 0o755)
	target := filepath.Join(dir, "sentinel.conf")
	os.WriteFile(target, []byte("good\n"), 0o644)
	h, err := selfheal.New(filepath.Join(t.TempDir(), "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Snapshot(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode()&(os.ModePerm|os.ModeSticky) != dirMode {
		t.Fatalf("setup: dir mode %v, want %v", fi.Mode(), dirMode)
	}
	cfg := config.Default()
	cfg.Mode, cfg.Enforcement = mode.Enforce, config.Enforcement{SelfHeal: true}
	a, path := appWithAudit(t, cfg, Meta{})
	a.healer, a.proc, a.sshd, a.freezer = h, hostProc{}, testSSHD(), &fakeFreezer{}
	a.contained, a.recentLimit = map[int32]*contState{}, 100
	a.healGate = writerSeesHostFile
	a.healDelay = func() { asAttacker(t, "rm -f "+target) } // the attacker's timed rm inside the heal delay
	return attackFx{a, target, path}
}

func mustNotBeRecreated(t *testing.T, f attackFx) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(f.target, &st); err == nil {
		b, _ := os.ReadFile(f.target)
		t.Fatalf("uid %d made phaged create %s (owner uid %d) with %q", attackerUID, f.target, st.Uid, b)
	}
}

// R4: in a group/world-writable directory the attacker replaces the admin's
// file with its own (so the gate sees it as the current owner), then deletes
// it during the heal delay. The agent must not recreate a root-owned file.
func TestAttackSharedDirReplaceThenDelete(t *testing.T) {
	f := sharedDirFx(t, 0o777)
	os.WriteFile(f.target, []byte("admin-later-edit\n"), 0o644)
	asAttacker(t, "rm -f "+f.target+" && echo x > "+f.target)
	f.fire(999999, attackerUID)
	mustNotBeRecreated(t, f)
}

// R4: sticky (/tmp-like) directory; the admin removed the sentinel; the
// attacker recreates it, then deletes it during the heal delay.
func TestAttackStickyDirRecreateDeleted(t *testing.T) {
	f := sharedDirFx(t, 0o777|os.ModeSticky)
	os.Remove(f.target)
	asAttacker(t, "echo x > "+f.target)
	f.fire(999999, attackerUID)
	mustNotBeRecreated(t, f)
}

// Rule (1) on its own, in a directory nobody else can write: the user owns
// her sentinel, writes it, then deletes it during the heal delay. A non-root
// writer's event must not make root recreate an absent file.
func TestAttackOwnerDeletesDuringHeal(t *testing.T) {
	f := newAttackFx(t, attackerUID)
	pid := spawnAttacker(t, "true")
	asAttacker(t, "echo x > "+f.target)
	f.a.healDelay = func() { asAttacker(t, "rm -f "+f.target) }
	f.fire(pid, attackerUID)
	mustNotBeRecreated(t, f)
}

// The dirty-bit rerun must heal with the uid of the writer whose event was
// folded in, not the first writer's. A root event's heal is in flight; the
// owner (uid 4242) writes and her event is folded into the rerun; before the
// rerun she deletes the file. The rerun runs for uid 4242, so the absent file
// must not be recreated (it would be if the rerun kept root's uid).
func TestRerunUsesFoldedInWriterUID(t *testing.T) {
	f := newAttackFx(t, attackerUID)  // alice-owned sentinel in her own 0700 dir
	alice := spawnAttacker(t, "true") // a live writer whose view is the host's
	release := make(chan struct{})
	calls := 0
	f.a.healDelay = func() {
		calls++
		switch calls {
		case 1:
			<-release // root's heal waits until alice's event is folded in
		case 2:
			asAttacker(t, "rm -f "+f.target) // before the rerun, alice deletes the file
		}
	}
	os.WriteFile(f.target, []byte("evil-by-root\n"), 0o600)
	f.a.respond(model.Event{Kind: kind.FileWrite, PID: 999999, PPID: 1, Comm: "sh",
		Creds: model.Credentials{UID: 0}, File: model.FileWrite{Path: f.target}},
		verdict.Verdict{Score: 0.95}, action.Notify)
	asAttacker(t, "echo alice-write > "+f.target)
	f.a.respond(model.Event{Kind: kind.FileWrite, PID: alice, PPID: 1, Comm: "sh",
		Creds: model.Credentials{UID: attackerUID}, File: model.FileWrite{Path: f.target}},
		verdict.Verdict{Score: 0.95}, action.Notify)
	close(release)
	f.a.healWG.Wait()

	if calls != 2 {
		t.Fatalf("heal ran %d times, want 2 (root's heal + one rerun for the folded-in event)", calls)
	}
	mustNotBeRecreated(t, f)
	recs := recordsOfKind(t, f.audit, "self_heal")
	if len(recs) != 2 || recs[0].Outcome != "healed" || !strings.HasPrefix(recs[1].Outcome, "failed:") {
		t.Fatalf("self_heal records = %+v, want healed then failed:<absent, non-root writer>", recs)
	}
}
