package app

import (
	"testing"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
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
func TestContainmentSafe(t *testing.T) {
	// A genuine no-session escalation: unprivileged uid now holds root euid,
	// no login behind it, ordinary service process.
	escalation := model.Event{
		Comm: "rootshell", ParentComm: "sh",
		Creds:   model.Credentials{UID: 999, EUID: 0},
		Session: model.Session{Interactive: false, LoginUID: -1},
	}
	if ok, _ := containmentSafe(escalation); !ok {
		t.Error("a no-session root escalation should be containable")
	}

	// Freeze-worthy non-escalation events (the matrix only routes high-confidence
	// kinds here) on an ordinary service process are now containable too.
	tamper := model.Event{
		Comm: "bash", ParentComm: "bash",
		Creds:   model.Credentials{UID: 0, EUID: 0},
		Session: model.Session{Interactive: false, LoginUID: -1},
	}
	if ok, _ := containmentSafe(tamper); !ok {
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
			Comm: "bash", ParentComm: "sshd", Creds: model.Credentials{UID: 1000, EUID: 0},
		}},
		{"systemd itself", model.Event{
			Comm: "systemd", Creds: model.Credentials{UID: 0, EUID: 0},
		}},
	}
	for _, c := range cases {
		if ok, _ := containmentSafe(c.ev); ok {
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
