package app

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
	"github.com/AzozzALFiras/Phage/internal/selfheal"
)

// These tests lock in the containment safety contract. They exist because
// enforce mode once froze SSH logins and locked a server out; the guardrail
// below must never regress. containmentSafe is now a pure safety gate (never the
// interactive admin path, never the control plane); WHICH event kinds ever reach
// a freeze is decided by the graduated-response matrix (see internal/policy/
// response), not here.
const (
	selfPID       int32 = 4000
	fakePhagedPID int32 = 667
)

// fakeProc is a scripted /proc.
type fakeProc struct {
	procs map[int32]fakeP
}

type fakeP struct {
	id    fileID
	nlink uint64
	link  string
	ppid  int32
	uid   int
	root  string // RootFileID: "host" = the host's inode at path, "other" = a different file, "" = unreadable
}

func (f fakeProc) get(pid int32) (fakeP, error) {
	p, ok := f.procs[pid]
	if !ok {
		return fakeP{}, os.ErrNotExist
	}
	return p, nil
}
func (f fakeProc) ExeID(pid int32) (fileID, uint64, string, error) {
	p, err := f.get(pid)
	return p.id, p.nlink, p.link, err
}
func (f fakeProc) PPID(pid int32) (int32, error) { p, err := f.get(pid); return p.ppid, err }
func (f fakeProc) UID(pid int32) (int, error)    { p, err := f.get(pid); return p.uid, err }
func (f fakeProc) RootFileID(pid int32, path string) (fileID, error) {
	p, err := f.get(pid)
	if err != nil {
		return fileID{}, err
	}
	switch p.root {
	case "host":
		return lstatID(path)
	case "other":
		return fileID{9999, 9999}, nil
	}
	return fileID{}, os.ErrPermission
}

var (
	sshdInode    = fileID{1, 100}
	sessionInode = fileID{1, 101}
	bashInode    = fileID{1, 7}
)

// A host with a real sshd tree, an upgraded (deleted-binary) sshd, and several
// impostors.
var testProc = fakeProc{procs: map[int32]fakeP{
	1:    {id: fileID{1, 1}, link: "/usr/lib/systemd/systemd", uid: 0},
	700:  {id: sshdInode, nlink: 1, link: "/usr/sbin/sshd", ppid: 1, uid: 0},                        // listener
	710:  {id: sessionInode, nlink: 1, link: "/usr/lib/openssh/sshd-session", ppid: 700, uid: 0},    // [priv]
	711:  {id: sessionInode, nlink: 1, link: "/usr/lib/openssh/sshd-session", ppid: 710, uid: 1000}, // [user]
	500:  {id: bashInode, nlink: 1, link: "/usr/bin/bash", ppid: 711, uid: 1000},                    // login shell
	702:  {id: fileID{1, 999}, nlink: 0, link: "/usr/sbin/sshd (deleted)", ppid: 1, uid: 0},         // pre-upgrade sshd
	666:  {id: fileID{1, 555}, nlink: 1, link: "/tmp/.x/sshd", ppid: 1, uid: 0},                     // payload named sshd
	720:  {id: sshdInode, nlink: 1, link: "/usr/sbin/sshd", ppid: 4321, uid: 0},                     // real binary, started by a shell
	4321: {id: bashInode, nlink: 1, link: "/usr/bin/bash", ppid: 1, uid: 0},
	730:  {id: sshdInode, nlink: 1, link: "/usr/sbin/sshd", ppid: 1, uid: 1000},    // started by init but not root
	667:  {id: fileID{1, 556}, nlink: 1, link: "/dev/shm/phaged", ppid: 1, uid: 0}, // payload named phaged
	800:  {id: bashInode, link: "/usr/bin/bash", ppid: 1, root: "host"},            // writer that sees the host file (e.g. unshare -m, no remount)
	801:  {id: bashInode, link: "/usr/bin/bash", ppid: 1, root: "other"},           // container writer: its own copy
	802:  {id: bashInode, link: "/usr/bin/bash", ppid: 1},                          // writer whose view is unreadable
}}

func testSSHD() *sshdIdentity {
	ids := map[string]fileID{"/usr/sbin/sshd": sshdInode, "/usr/lib/openssh/sshd-session": sessionInode}
	s := &sshdIdentity{paths: sshdExes, stat: func(p string) (fileID, error) {
		if id, ok := ids[p]; ok {
			return id, nil
		}
		return fileID{}, os.ErrNotExist
	}}
	s.refresh()
	return s
}

func TestSSHDIdentityByInodeAndAncestry(t *testing.T) {
	s := testSSHD()
	for pid, want := range map[int32]bool{
		700: true,  // listener: sshd inode, parent init, root
		711: true,  // user session: chain 711 -> 710 -> 700 -> init
		702: true,  // binary replaced by an upgrade: unlinked listed path
		666: false, // named sshd, other inode
		720: false, // real binary, but not started by init
		730: false, // started by init, but not root
		500: false, // the shell itself is not sshd
	} {
		if got := s.verified(testProc, pid); got != want {
			t.Errorf("verified(%d) = %v, want %v", pid, got, want)
		}
	}
}

func TestContainmentSafe(t *testing.T) {
	sshd := testSSHD()
	containable := []struct {
		name string
		ev   model.Event
	}{
		{"no-session root escalation", model.Event{PID: 900, PPID: 4321, Comm: "rootshell", ParentComm: "bash",
			Creds: model.Credentials{UID: 999, EUID: 0}, Session: model.Session{LoginUID: -1}}},
		{"payload named phaged", model.Event{PID: fakePhagedPID, Comm: "phaged", PPID: 1, ParentComm: "systemd-x"}},
		{"child of a fake phaged", model.Event{PID: 901, PPID: fakePhagedPID, Comm: "sh", ParentComm: "phaged"}},
		{"real sshd binary run by a user shell, renamed", model.Event{PID: 720, PPID: 4321, Comm: "x", ParentComm: "bash"}},
	}
	for _, c := range containable {
		if ok, why := containmentSafe(c.ev, selfPID, testProc, sshd); !ok {
			t.Errorf("%s: should be containable, got skipped (%s)", c.name, why)
		}
	}
	never := []struct {
		name string
		ev   model.Event
	}{
		{"interactive admin path", model.Event{PID: 902, Session: model.Session{Interactive: true, LoginUID: 1000}}},
		{"the agent itself, by pid", model.Event{PID: selfPID, Comm: "anything"}},
		{"child of the agent", model.Event{PID: 903, PPID: selfPID, Comm: "anything"}},
		{"verified sshd listener", model.Event{PID: 700, PPID: 1, Comm: "sshd"}},
		{"shell under a verified sshd session", model.Event{PID: 500, PPID: 711, Comm: "bash", ParentComm: "sshd-session"}},
		{"upgraded (deleted-binary) sshd", model.Event{PID: 702, PPID: 1, Comm: "sshd"}},
		{"systemd by name", model.Event{PID: 904, Comm: "systemd"}},
		// Never contained (a false negative here is a lockout) but logged as
		// UNVERIFIED — see the WARNING line.
		{"payload named sshd (unverified, logged)", model.Event{PID: 666, PPID: 1, Comm: "sshd"}},
	}
	for _, c := range never {
		if ok, _ := containmentSafe(c.ev, selfPID, testProc, sshd); ok {
			t.Errorf("%s: must NOT be containable", c.name)
		}
	}
	if _, why := containmentSafe(model.Event{PID: 666, PPID: 1, Comm: "sshd"}, selfPID, testProc, sshd); !strings.Contains(why, "unverified") {
		t.Errorf("an impostor sshd must be reported as unverified, got %q", why)
	}
}

func TestWriterSeesHostFile(t *testing.T) {
	host := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(host, []byte("k\n"), 0o600)
	const owner, user = 0, 4242
	if ok, why := writerSeesHostFile(testProc, 800, host, user, owner); !ok {
		t.Errorf("writer resolving to the host inode (e.g. unshare -m without remounts) must heal: %s", why)
	}
	if ok, _ := writerSeesHostFile(testProc, 801, host, 0, owner); ok {
		t.Error("a writer whose path resolves to a different file must not trigger a host heal, even as root")
	}
	// View unreadable (802) or writer gone (31337): only a writer that could
	// have written the host file falls back to the content check.
	for _, pid := range []int32{802, 31337} {
		if ok, _ := writerSeesHostFile(testProc, pid, host, 0, owner); !ok {
			t.Errorf("pid %d, root writer: fallback must allow the content check", pid)
		}
		if ok, _ := writerSeesHostFile(testProc, pid, host, user, user); !ok {
			t.Errorf("pid %d, writer is the file owner: fallback must allow the content check", pid)
		}
		if ok, _ := writerSeesHostFile(testProc, pid, host, user, owner); ok {
			t.Errorf("pid %d, unprivileged non-owner writer: fallback must NOT heal (it cannot have written the host file)", pid)
		}
	}
}

// The real /proc implementation: our own root is the host root, so a file
// resolves to its own inode.
func TestHostProcRootFileID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("x"), 0o600)
	got, err := hostProc{}.RootFileID(int32(os.Getpid()), p)
	if err != nil {
		t.Skipf("openat2/RESOLVE_IN_ROOT unavailable here: %v", err)
	}
	want, _ := lstatID(p)
	if got != want {
		t.Errorf("RootFileID = %+v, want %+v", got, want)
	}
	link := filepath.Join(filepath.Dir(p), "l")
	os.Symlink(p, link)
	// A trailing symlink is not followed: like the host-side lstat, it names
	// the link itself, so a link to the host file never "matches" it.
	lid, err := hostProc{}.RootFileID(int32(os.Getpid()), link)
	if wantLink, _ := lstatID(link); err != nil || lid != wantLink || lid == want {
		t.Errorf("RootFileID(link) = %+v (%v), want the link's own inode %+v", lid, err, wantLink)
	}
}

func TestGateDowngradesUnarmedRungs(t *testing.T) {
	mk := func(m mode.Mode, e config.Enforcement) *App {
		c := config.Default()
		c.Mode, c.Enforcement = m, e
		return &App{cfg: c}
	}
	all := config.Enforcement{Isolate: true, Freeze: true}
	cases := []struct {
		name string
		app  *App
		in   action.Type
		want action.Type
	}{
		{"enforce, nothing armed: isolate alerts", mk(mode.Enforce, config.Enforcement{}), action.Isolate, action.Notify},
		{"enforce, nothing armed: freeze alerts", mk(mode.Enforce, config.Enforcement{}), action.Freeze, action.Notify},
		{"enforce, isolate armed", mk(mode.Enforce, config.Enforcement{Isolate: true}), action.Isolate, action.Isolate},
		{"enforce, only isolate armed: freeze alerts", mk(mode.Enforce, config.Enforcement{Isolate: true}), action.Freeze, action.Notify},
		{"enforce, freeze armed", mk(mode.Enforce, config.Enforcement{Freeze: true}), action.Freeze, action.Freeze},
		{"alert mode never acts even if keys set", mk(mode.Alert, all), action.Freeze, action.Notify},
		{"kill is never armable", mk(mode.Enforce, all), action.Kill, action.Notify},
		{"notify passes through", mk(mode.Alert, config.Enforcement{}), action.Notify, action.Notify},
	}
	for _, c := range cases {
		if got, _ := c.app.gate(c.in); got != c.want {
			t.Errorf("%s: gate(%s) = %s, want %s", c.name, c.in, got, c.want)
		}
	}
}

func readAudit(t *testing.T, path string) []audit.Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line is not JSON: %v (%q)", err, line)
		}
		out = append(out, e)
	}
	return out
}

func appWithAudit(t *testing.T, c config.Config, meta Meta) (*App, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	aw, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aw.Close() })
	return &App{cfg: c, audit: aw, meta: meta, selfPID: selfPID}, path
}

func TestStartupRecordWhenArmed(t *testing.T) {
	c := config.Default()
	c.Mode = mode.Enforce
	c.Source = config.Source{Path: "/etc/phage/phage.yaml", SHA256: strings.Repeat("ab", 32)}
	a, path := appWithAudit(t, c, Meta{Version: "v-test"})
	if err := a.announceStartup([]string{config.FeatureIsolate, config.FeatureSelfHeal}, []string{config.FeatureSelfProtect}); err != nil {
		t.Fatal(err)
	}
	recs := readAudit(t, path)
	if len(recs) != 2 || recs[0].Kind != audit.KindEnforcementArmed || recs[1].Kind != audit.KindStartup {
		t.Fatalf("records = %+v, want enforcement_armed then startup", recs)
	}
	for _, e := range recs {
		if e.Status != audit.StatusArmed || e.Mode != "enforce" || e.Version != "v-test" ||
			e.ConfigPath != c.Source.Path || e.ConfigSHA256 != c.Source.SHA256 {
			t.Errorf("record missing provenance/status: %+v", e)
		}
		if strings.Join(e.Features, ",") != "isolate,self_heal" || strings.Join(e.Failed, ",") != "self_protect" {
			t.Errorf("features=%v failed=%v", e.Features, e.Failed)
		}
	}
}

func TestStartupRecordOnEveryStart(t *testing.T) {
	a, path := appWithAudit(t, config.Default(), Meta{Version: "v"})
	if err := a.announceStartup(nil, nil); err != nil {
		t.Fatal(err)
	}
	recs := readAudit(t, path)
	if len(recs) != 1 || recs[0].Kind != audit.KindStartup || recs[0].Status != audit.StatusNone {
		t.Fatalf("records = %+v, want one startup record with status none", recs)
	}

	c := config.Default()
	c.Mode = mode.Enforce
	a, path = appWithAudit(t, c, Meta{})
	a.announceStartup(nil, []string{config.FeatureSelfProtect})
	if recs := readAudit(t, path); len(recs) != 1 || recs[0].Status != audit.StatusFailed {
		t.Fatalf("all requested features failed: records = %+v, want one startup record status failed (no ARMED record)", recs)
	}
}

func TestStartupRecordsDowngrade(t *testing.T) {
	c := config.Default()
	c.Mode = mode.Alert
	a, path := appWithAudit(t, c, Meta{Disarmed: []string{"freeze"}, DowngradedFrom: mode.Enforce})
	if err := a.announceStartup(nil, nil); err != nil {
		t.Fatal(err)
	}
	recs := readAudit(t, path)
	if len(recs) != 2 || recs[0].Kind != audit.KindDisarmed || strings.Join(recs[0].Disarmed, ",") != "freeze" {
		t.Fatalf("records = %+v, want a disarmed record first", recs)
	}
}

func TestStartupRecordFailureIsFatal(t *testing.T) {
	a, _ := appWithAudit(t, config.Default(), Meta{})
	a.audit.Close() // writes now fail
	if err := a.announceStartup([]string{config.FeatureFreeze}, nil); err == nil {
		t.Fatal("a startup/arming record that cannot be written must be fatal")
	}
}

func TestSupervisorIsPIDOneOnly(t *testing.T) {
	a := &App{selfPID: selfPID, getppid: func() int { return 1234 }}
	if !a.isSupervisor(1) {
		t.Error("pid 1 must be trusted to stop the agent")
	}
	if a.isSupervisor(1234) || a.isSupervisor(4321) {
		t.Error("without dev.trust_launcher_signals only pid 1 is the supervisor")
	}
	a.cfg.Dev.TrustLauncherSignals = true
	if !a.isSupervisor(1234) {
		t.Error("with dev.trust_launcher_signals the current parent is trusted")
	}
	// The parent is re-read at decision time: once the launcher has exited
	// (reparented to 1), its old pid is no longer trusted.
	a.getppid = func() int { return 1 }
	if a.isSupervisor(1234) {
		t.Error("a launcher that has gone away must not stay trusted")
	}
	if !a.isSelf(selfPID) || a.isSelf(fakePhagedPID) {
		t.Error("isSelf must match the agent's tgid only")
	}
}

// A path or comm is attacker-chosen; one with a newline must not be able to
// forge a second journal line.
func TestRespondLogCannotBeLineForged(t *testing.T) {
	var buf strings.Builder
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()

	c := config.Default()
	c.Mode = mode.Alert
	a := &App{cfg: c, contained: map[int32]*contState{}, recentLimit: 10}
	ev := model.Event{
		Kind: kind.FileWrite, PID: 77, Comm: "x\nCRITICAL fake",
		File: model.FileWrite{Path: "/etc/cron.d/a\nCRITICAL self-defense: forged line"},
	}
	a.respond(ev, verdict.Verdict{Score: 0.9}, action.Notify)

	out := strings.TrimSuffix(buf.String(), "\n")
	if strings.Contains(out, "\n") {
		t.Fatalf("one verdict produced more than one log line:\n%s", out)
	}
	if !strings.Contains(out, `\nCRITICAL self-defense`) {
		t.Errorf("the newline in the path should appear escaped: %s", out)
	}
	// Escaped exactly once: no quoted-inside-quoted path.
	if !strings.Contains(out, `(wrote /etc/cron.d/a\nCRITICAL self-defense: forged line)`) || strings.Contains(out, `\\n`) {
		t.Errorf("the path should be escaped once, not double-quoted: %s", out)
	}
}

type fakeFreezer struct{ frozen []int32 }

func (f *fakeFreezer) Freeze(pid int32) error { f.frozen = append(f.frozen, pid); return nil }
func (f *fakeFreezer) Thaw(int32) error       { return nil }

type fakeIsolator struct {
	isolated []int32
	err      error
}

func (f *fakeIsolator) Isolate(pid int32) error {
	if f.err != nil {
		return f.err
	}
	f.isolated = append(f.isolated, pid)
	return nil
}
func (f *fakeIsolator) Release(int32) error { return nil }

// The audit record is written after actuation and says what the matrix asked
// for, what was applied and how it went — and `phage events` shows the same.
func TestResponseRecordAfterActuation(t *testing.T) {
	ordinary := model.Event{Kind: kind.Connect, PID: 900, PPID: 4321, Comm: "nc", ParentComm: "bash"}
	cases := []struct {
		name               string
		enf                config.Enforcement
		netq               *fakeIsolator
		ev                 model.Event
		requested          action.Type
		wantAction         action.Type
		wantOutcomePrefix  string
		wantFroze, wantIso bool
	}{
		{"isolate armed and applied", config.Enforcement{Isolate: true}, &fakeIsolator{}, ordinary,
			action.Isolate, action.Isolate, "contained", false, true},
		{"isolate not armed", config.Enforcement{}, nil, ordinary,
			action.Isolate, action.Notify, "skipped:isolate not armed", false, false},
		{"isolate fails", config.Enforcement{Isolate: true}, &fakeIsolator{err: os.ErrPermission}, ordinary,
			action.Isolate, action.Notify, "failed:isolate", false, false},
		{"isolate unavailable, freeze armed: falls back", config.Enforcement{Isolate: true, Freeze: true}, nil, ordinary,
			action.Isolate, action.Freeze, "contained", true, false},
		{"isolate of verified sshd skipped", config.Enforcement{Isolate: true}, &fakeIsolator{},
			model.Event{Kind: kind.Connect, PID: 700, PPID: 1, Comm: "sshd"},
			action.Isolate, action.Notify, "skipped:control-plane", false, false},
		{"freeze armed", config.Enforcement{Freeze: true}, nil, ordinary,
			action.Freeze, action.Freeze, "contained", true, false},
		{"notify", config.Enforcement{}, nil, ordinary,
			action.Notify, action.Notify, "notified", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Mode, cfg.Enforcement = mode.Enforce, c.enf
			a, path := appWithAudit(t, cfg, Meta{})
			fz := &fakeFreezer{}
			a.freezer, a.proc, a.sshd = fz, testProc, testSSHD()
			a.contained, a.recentLimit = map[int32]*contState{}, 10
			if c.netq != nil {
				a.netq = c.netq
			}
			a.respond(c.ev, verdict.Verdict{Score: 0.95}, c.requested)

			recs := readAudit(t, path)
			if len(recs) != 1 {
				t.Fatalf("records = %+v", recs)
			}
			r := recs[0]
			if r.Requested != string(c.requested) || r.Action != string(c.wantAction) || !strings.HasPrefix(r.Outcome, c.wantOutcomePrefix) {
				t.Errorf("record requested=%s action=%s outcome=%q; want %s/%s/%s*", r.Requested, r.Action, r.Outcome,
					c.requested, c.wantAction, c.wantOutcomePrefix)
			}
			if (len(fz.frozen) > 0) != c.wantFroze {
				t.Errorf("froze=%v, want %v", fz.frozen, c.wantFroze)
			}
			if c.netq != nil && (len(c.netq.isolated) > 0) != c.wantIso {
				t.Errorf("isolated=%v, want %v", c.netq.isolated, c.wantIso)
			}
			got := a.RecentAlerts(1)[0]
			if got.Requested != r.Requested || got.Action != r.Action || got.Outcome != r.Outcome || got.Reason != r.Reason {
				t.Errorf("phage events disagrees with the audit trail: %+v vs %+v", got, r)
			}
		})
	}
}

// armFeatures must call exactly the loaders config.Armed allows — never one
// for a feature that is off or not allowed in the current mode.
func TestArmFeaturesArmsOnlyWhatArmedAllows(t *testing.T) {
	all := config.Enforcement{Isolate: true, Freeze: true, SelfHeal: true, SelfProtect: true}
	cases := []struct {
		name string
		m    mode.Mode
		enf  config.Enforcement
		ht   bool
	}{
		{"learn, nothing", mode.Learn, config.Enforcement{}, false},
		{"alert, honeytokens only", mode.Alert, config.Enforcement{}, true},
		{"alert, enforcement keys bypassing Validate", mode.Alert, all, true},
		{"learn, everything bypassing Validate", mode.Learn, all, true},
		{"enforce, nothing", mode.Enforce, config.Enforcement{}, false},
		{"enforce, isolate+heal", mode.Enforce, config.Enforcement{Isolate: true, SelfHeal: true}, false},
		{"enforce, everything", mode.Enforce, all, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Mode, cfg.Enforcement, cfg.Deception.Honeytokens = c.m, c.enf, c.ht
			a := &App{cfg: cfg}
			called := map[string]bool{}
			undone := map[string]bool{}
			ar := armers{
				honeytokens: func() (func(), string, error) {
					called[config.FeatureHoneytokens] = true
					return func() { undone[config.FeatureHoneytokens] = true }, "fake", nil
				},
				selfProtect: func() (func(), error) {
					called[config.FeatureSelfProtect] = true
					return func() { undone[config.FeatureSelfProtect] = true }, nil
				},
				isolate: func() (isolator, func(), error) {
					called[config.FeatureIsolate] = true
					return &fakeIsolator{}, func() { undone[config.FeatureIsolate] = true }, nil
				},
				selfHeal: func() (*selfheal.Store, error) {
					called[config.FeatureSelfHeal] = true
					return nil, nil
				},
			}
			armed, failed, disarm := a.armFeatures(ar)
			for _, f := range []string{config.FeatureIsolate, config.FeatureSelfHeal, config.FeatureSelfProtect, config.FeatureHoneytokens} {
				if called[f] != cfg.Armed(f) {
					t.Errorf("%s loader called=%v, but Armed=%v", f, called[f], cfg.Armed(f))
				}
			}
			var want []string
			for _, f := range []string{config.FeatureHoneytokens, config.FeatureSelfProtect, config.FeatureIsolate, config.FeatureFreeze, config.FeatureSelfHeal} {
				if cfg.Armed(f) {
					want = append(want, f)
				}
			}
			if strings.Join(armed, ",") != strings.Join(want, ",") || len(failed) != 0 {
				t.Errorf("armed=%v failed=%v, want %v", armed, failed, want)
			}
			if (a.netq != nil) != cfg.Armed(config.FeatureIsolate) {
				t.Errorf("netq set=%v, Armed(isolate)=%v", a.netq != nil, cfg.Armed(config.FeatureIsolate))
			}
			disarm()
			for f := range called {
				if f != config.FeatureSelfHeal && !undone[f] {
					t.Errorf("%s armed but not disarmed by the cleanup", f)
				}
			}
		})
	}
}

func TestArmFeaturesReportsFailures(t *testing.T) {
	cfg := config.Default()
	cfg.Mode, cfg.Enforcement = mode.Enforce, config.Enforcement{Isolate: true, SelfProtect: true}
	a := &App{cfg: cfg}
	boom := os.ErrPermission
	armed, failed, _ := a.armFeatures(armers{
		selfProtect: func() (func(), error) { return nil, boom },
		isolate:     func() (isolator, func(), error) { return nil, nil, boom },
	})
	if len(armed) != 0 || strings.Join(failed, ",") != "self_protect,isolate" {
		t.Errorf("armed=%v failed=%v", armed, failed)
	}
	if a.netq != nil {
		t.Error("a failed isolate loader must leave netq nil")
	}
}

// healFixture is an enforce-mode App with self-heal armed over a real
// snapshotted file, the scripted /proc, and no heal delay.
type healFixture struct {
	a      *App
	target string
	audit  string
}

func newHealFixture(t *testing.T) healFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".ssh")
	os.Mkdir(dir, 0o700)
	target := filepath.Join(dir, "authorized_keys")
	os.WriteFile(target, []byte("good\n"), 0o600)
	h, err := selfheal.New(filepath.Join(root, "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Snapshot(target); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Mode, cfg.Enforcement = mode.Enforce, config.Enforcement{SelfHeal: true}
	a, path := appWithAudit(t, cfg, Meta{})
	a.healer, a.proc, a.sshd, a.freezer = h, testProc, testSSHD(), &fakeFreezer{}
	a.contained, a.recentLimit = map[int32]*contState{}, 100
	a.healGate, a.healDelay = writerSeesHostFile, func() {}
	return healFixture{a: a, target: target, audit: path}
}

func (f healFixture) write(t *testing.T, pid int32, want action.Type) {
	t.Helper()
	os.WriteFile(f.target, []byte("evil\n"), 0o600)
	f.a.respond(model.Event{Kind: kind.FileWrite, PID: pid, PPID: 1, Comm: "sh",
		File: model.FileWrite{Path: f.target}}, verdict.Verdict{Score: 0.95}, want)
}

func recordsOfKind(t *testing.T, path, k string) []audit.Entry {
	var out []audit.Entry
	for _, e := range readAudit(t, path) {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func TestSelfHealIsAudited(t *testing.T) {
	f := newHealFixture(t)
	f.write(t, 800, action.Notify)
	f.a.healWG.Wait()
	if b, _ := os.ReadFile(f.target); string(b) != "good\n" {
		t.Fatalf("not healed: %q", b)
	}
	recs := recordsOfKind(t, f.audit, audit.KindSelfHeal)
	if len(recs) != 1 {
		t.Fatalf("self_heal records = %+v, want 1", recs)
	}
	r := recs[0]
	if r.Action != "self_heal" || r.Outcome != "healed" || r.Path != f.target || r.Evidence == "" || r.PID != 800 {
		t.Errorf("record = %+v, want action self_heal outcome healed with path and evidence", r)
	}
	if b, err := os.ReadFile(r.Evidence); err != nil || string(b) != "evil\n" {
		t.Errorf("evidence %q = %q (%v)", r.Evidence, b, err)
	}
}

func TestSelfHealFailureIsAudited(t *testing.T) {
	f := newHealFixture(t)
	os.Remove(f.target)
	os.Mkdir(f.target, 0o700) // a directory cannot be restored over
	f.a.respond(model.Event{Kind: kind.FileWrite, PID: 802, PPID: 1, Comm: "sh",
		File: model.FileWrite{Path: f.target}}, verdict.Verdict{Score: 0.95}, action.Notify)
	f.a.healWG.Wait()
	recs := recordsOfKind(t, f.audit, audit.KindSelfHeal)
	if len(recs) != 1 || !strings.HasPrefix(recs[0].Outcome, "failed:") {
		t.Fatalf("self_heal records = %+v, want one failed:<err>", recs)
	}
}

// The gate must be consulted: a writer whose path names a different file (its
// own namespace's copy) must not make the agent rewrite the host file.
func TestSelfHealSkippedForWriterOfADifferentFile(t *testing.T) {
	f := newHealFixture(t)
	f.write(t, 801, action.Notify)
	f.a.healWG.Wait()
	if b, _ := os.ReadFile(f.target); string(b) != "evil\n" {
		t.Fatalf("host file was rewritten for a writer of a different file: %q", b)
	}
	if n := len(recordsOfKind(t, f.audit, audit.KindSelfHeal)); n != 0 {
		t.Errorf("%d self_heal records; a gated-off heal must not run", n)
	}
	resp := recordsOfKind(t, f.audit, audit.KindResponse)
	if len(resp) != 1 || !strings.Contains(resp[0].Reason, "self-heal skipped") {
		t.Errorf("response reason should note the skipped heal: %+v", resp)
	}
}

// A burst of writes during a running heal costs one extra heal (dirty bit),
// not one heal per write — and none is lost.
func TestSelfHealBurstIsDeduplicated(t *testing.T) {
	f := newHealFixture(t)
	gate := make(chan struct{})
	f.a.healDelay = func() { <-gate }
	for i := 0; i < 5; i++ {
		f.write(t, 800, action.Notify)
	}
	close(gate)
	f.a.healWG.Wait()
	recs := recordsOfKind(t, f.audit, audit.KindSelfHeal)
	if len(recs) != 2 {
		t.Fatalf("%d heals for a burst of 5 writes, want 2 (the heal + one dirty rerun): %+v", len(recs), recs)
	}
	if b, _ := os.ReadFile(f.target); string(b) != "good\n" {
		t.Fatalf("not healed: %q", b)
	}
}

// A write by a process that is already contained still heals the file and is
// still audited (the early de-dup return used to skip both).
func TestAlreadyContainedWriterStillHealsAndAudits(t *testing.T) {
	f := newHealFixture(t)
	f.a.contained[800] = &contState{rung: action.Freeze, last: time.Now(), comm: "sh"}
	f.write(t, 800, action.Notify)
	f.a.healWG.Wait()
	if b, _ := os.ReadFile(f.target); string(b) != "good\n" {
		t.Fatalf("contained writer's write not healed: %q", b)
	}
	resp := recordsOfKind(t, f.audit, audit.KindResponse)
	if len(resp) != 1 || resp[0].Outcome != "already_contained" || resp[0].Action != string(action.Freeze) {
		t.Errorf("response records = %+v, want one already_contained record", resp)
	}
	if len(recordsOfKind(t, f.audit, audit.KindSelfHeal)) != 1 {
		t.Error("the heal must be audited")
	}
}
