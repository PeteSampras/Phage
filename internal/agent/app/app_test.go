package app

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
)

// These tests lock in the containment safety contract. They exist because
// enforce mode once froze SSH logins and locked a server out; the guardrail
// below must never regress. containmentSafe is now a pure safety gate (never the
// interactive admin path, never the control plane); WHICH event kinds ever reach
// a freeze is decided by the graduated-response matrix (see internal/policy/
// response), not here.
const (
	selfPID         int32 = 4000
	sshdPID         int32 = 700
	sshdSessionPID  int32 = 701
	upgradedSSHDPID int32 = 702
	fakeSSHDPID     int32 = 666
	fakePhagedPID   int32 = 667
)

// fakeExe stands in for /proc/<pid>/exe.
func fakeExe(pid int32) string {
	switch pid {
	case sshdPID:
		return "/usr/sbin/sshd"
	case sshdSessionPID:
		return "/usr/lib/openssh/sshd-session"
	case upgradedSSHDPID:
		return "/usr/sbin/sshd (deleted)"
	case fakeSSHDPID:
		return "/tmp/.x/sshd"
	case fakePhagedPID:
		return "/dev/shm/phaged"
	}
	return "/usr/bin/bash"
}

func TestContainmentSafe(t *testing.T) {
	// A genuine no-session escalation: unprivileged uid now holds root euid,
	// no login behind it, ordinary service process.
	escalation := model.Event{
		Comm: "rootshell", ParentComm: "sh",
		Creds:   model.Credentials{UID: 999, EUID: 0},
		Session: model.Session{Interactive: false, LoginUID: -1},
	}
	if ok, _ := containmentSafe(escalation, selfPID, fakeExe); !ok {
		t.Error("a no-session root escalation should be containable")
	}

	// Freeze-worthy non-escalation events (the matrix only routes high-confidence
	// kinds here) on an ordinary service process are now containable too.
	tamper := model.Event{
		Comm: "bash", ParentComm: "bash",
		Creds:   model.Credentials{UID: 0, EUID: 0},
		Session: model.Session{Interactive: false, LoginUID: -1},
	}
	if ok, _ := containmentSafe(tamper, selfPID, fakeExe); !ok {
		t.Error("a non-interactive, non-control-plane process should be containable")
	}

	// The hard guardrails: never the admin's own session, never the control plane.
	cases := []struct {
		name string
		ev   model.Event
	}{
		{"interactive admin path", model.Event{
			Comm: "rootshell", Creds: model.Credentials{UID: 1000, EUID: 0},
			Session: model.Session{Interactive: true, LoginUID: 1000},
		}},
		{"sshd child (control plane)", model.Event{
			PID: 500, PPID: sshdPID, Comm: "bash", ParentComm: "sshd", Creds: model.Credentials{UID: 1000, EUID: 0},
		}},
		{"sshd itself, by exe", model.Event{
			PID: sshdPID, Comm: "sshd", Creds: model.Credentials{UID: 0, EUID: 0},
		}},
		{"sshd-session (OpenSSH >= 9.8) child", model.Event{
			PID: 501, PPID: sshdSessionPID, Comm: "bash", ParentComm: "sshd-session",
		}},
		{"sshd after a package upgrade (deleted binary)", model.Event{
			PID: upgradedSSHDPID, Comm: "sshd",
		}},
		{"the agent itself, by pid", model.Event{
			PID: selfPID, Comm: "anything",
		}},
		{"systemd itself", model.Event{
			Comm: "systemd", Creds: model.Credentials{UID: 0, EUID: 0},
		}},
	}
	for _, c := range cases {
		if ok, _ := containmentSafe(c.ev, selfPID, fakeExe); ok {
			t.Errorf("%s: must NOT be containable", c.name)
		}
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

func TestContainmentIgnoresSpoofedComm(t *testing.T) {
	cases := []struct {
		name string
		ev   model.Event
	}{
		{"payload named sshd", model.Event{PID: fakeSSHDPID, Comm: "sshd", PPID: 1, ParentComm: "bash"}},
		{"child of a fake sshd", model.Event{PID: 900, PPID: fakeSSHDPID, Comm: "sh", ParentComm: "sshd"}},
		{"payload named phaged", model.Event{PID: fakePhagedPID, Comm: "phaged", PPID: 1, ParentComm: "bash"}},
		{"child of a fake phaged", model.Event{PID: 901, PPID: fakePhagedPID, Comm: "sh", ParentComm: "phaged"}},
	}
	for _, c := range cases {
		if ok, why := containmentSafe(c.ev, selfPID, fakeExe); !ok {
			t.Errorf("%s: exempted from containment (%s); comm must not grant trust", c.name, why)
		}
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
}
