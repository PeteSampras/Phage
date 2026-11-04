package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/audit"
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

func TestAnnounceEnforcementWritesAuditRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	aw, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Mode = mode.Enforce
	a := &App{cfg: c, audit: aw}
	a.announceEnforcement([]string{config.FeatureIsolate, config.FeatureSelfHeal}, []string{config.FeatureSelfProtect})
	aw.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e audit.Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("audit line is not one JSON record: %v (%q)", err, raw)
	}
	if e.Kind != audit.KindEnforcementArmed || e.Mode != "enforce" {
		t.Errorf("kind/mode = %q/%q, want enforcement_armed/enforce", e.Kind, e.Mode)
	}
	if strings.Join(e.Features, ",") != "isolate,self_heal" || strings.Join(e.Failed, ",") != "self_protect" {
		t.Errorf("features=%v failed=%v", e.Features, e.Failed)
	}
}

func TestAnnounceEnforcementSilentInAuditWhenNothingArmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	aw, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: config.Default(), audit: aw}
	a.announceEnforcement(nil, nil)
	aw.Close()
	if raw, _ := os.ReadFile(path); len(raw) != 0 {
		t.Errorf("no feature armed, but an audit record was written: %q", raw)
	}
}

// An attacker picks its own comm. Naming a payload "sshd" or "phaged" (or
// parenting it under one) must not buy an exemption from containment.
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

func TestSupervisorIsByPID(t *testing.T) {
	a := &App{selfPID: selfPID, launcherPID: 1234}
	if !a.isSupervisor(1) || !a.isSupervisor(1234) {
		t.Error("pid 1 and the launcher must be trusted to stop the agent")
	}
	if a.isSupervisor(4321) {
		t.Error("an arbitrary pid (whatever its comm) must not be trusted as the supervisor")
	}
	if b := (&App{launcherPID: 0}); b.isSupervisor(0) {
		t.Error("an unknown launcher (0) must not make pid 0 trusted")
	}
	if !a.isSelf(selfPID) || a.isSelf(fakePhagedPID) {
		t.Error("isSelf must match the agent's tgid only")
	}
}
