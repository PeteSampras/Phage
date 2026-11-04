package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/policy/mode"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "phage.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadOverlaysDefaults(t *testing.T) {
	// Only some fields are set; the rest must keep their defaults.
	p := writeTemp(t, `
mode: enforce
thresholds:
  notify: 0.5
  contain: 0.9
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != mode.Enforce {
		t.Errorf("Mode = %v, want enforce", cfg.Mode)
	}
	if cfg.Thresholds.Notify != 0.5 || cfg.Thresholds.Contain != 0.9 {
		t.Errorf("thresholds = %+v, want {0.5 0.9}", cfg.Thresholds)
	}
	// Untouched field keeps the default.
	if cfg.ControlPath != Default().ControlPath {
		t.Errorf("ControlPath = %q, want default %q", cfg.ControlPath, Default().ControlPath)
	}
}

func TestLoadRejectsInvertedThresholds(t *testing.T) {
	// notify above contain is nonsensical: a score could demand containment
	// without ever crossing the alert line. Must fail loudly, not silently run.
	p := writeTemp(t, "thresholds:\n  notify: 0.9\n  contain: 0.4\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when notify > contain")
	}
}

func TestLoadRejectsOutOfRange(t *testing.T) {
	p := writeTemp(t, "thresholds:\n  contain: 1.7\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when a threshold is out of [0,1]")
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	// A typo like "treshold" must not be silently ignored on a security daemon.
	p := writeTemp(t, "treshold: 0.5\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error on an unknown config key")
	}
}

func TestLoadRejectsBadMode(t *testing.T) {
	p := writeTemp(t, "mode: paranoid\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error on an unknown mode")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for a missing file")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	// The committed example must always be a valid, loadable config.
	if _, err := Load("../../../configs/phage.example.yaml"); err != nil {
		t.Fatalf("configs/phage.example.yaml does not load: %v", err)
	}
}

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must validate: %v", err)
	}
}

func TestDefaultArmsNothing(t *testing.T) {
	// The default posture is learn → alert: no acting feature is on, and even in
	// enforce mode an untouched config arms nothing.
	d := Default()
	if got := d.Enforcement.Requested(); len(got) != 0 {
		t.Fatalf("Default() requests enforcement features %v, want none", got)
	}
	d.Mode = mode.Enforce
	for _, f := range []string{FeatureIsolate, FeatureFreeze, FeatureSelfHeal, FeatureSelfProtect, FeatureHoneytokens} {
		if d.Armed(f) {
			t.Errorf("enforce mode with default enforcement block arms %s", f)
		}
	}
}

func TestLoadEnforcementBlock(t *testing.T) {
	p := writeTemp(t, `
mode: enforce
release_after: 120
enforcement:
  isolate: true
  freeze: false
  self_heal: true
  self_protect: true
  honeytokens: true
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Enforcement{Isolate: true, SelfHeal: true, SelfProtect: true, Honeytokens: true}
	if cfg.Enforcement != want {
		t.Errorf("Enforcement = %+v, want %+v", cfg.Enforcement, want)
	}
	if cfg.ReleaseAfter != 120 {
		t.Errorf("ReleaseAfter = %d, want 120", cfg.ReleaseAfter)
	}
	if !cfg.Armed(FeatureIsolate) || cfg.Armed(FeatureFreeze) || !cfg.Armed(FeatureSelfHeal) {
		t.Errorf("Armed() does not follow the enforcement keys: %+v", cfg.Enforcement)
	}
}

func TestLoadRefusesActingFeatureOutsideEnforce(t *testing.T) {
	// Fail closed: an acting feature switched on in learn or alert mode is a
	// startup error, never silently honoured (upstream ran self-heal in alert).
	for _, m := range []string{"learn", "alert"} {
		for _, key := range []string{"isolate", "freeze", "self_heal", "self_protect", "honeytokens"} {
			p := writeTemp(t, "mode: "+m+"\nenforcement:\n  "+key+": true\n")
			if _, err := Load(p); err == nil {
				t.Errorf("mode %s with enforcement.%s: true loaded; want an error", m, key)
			}
		}
	}
}

func TestValidateRefusesFlagArmedOutsideEnforce(t *testing.T) {
	// The CLI path (-heal/-protect/-honeytokens) goes through Validate too.
	c := Default()
	c.Mode = mode.Alert
	c.Enforcement.SelfHeal = true
	if err := c.Validate(); err == nil {
		t.Fatal("alert mode with self-heal on must not validate")
	}
	c.Mode = mode.Enforce
	if err := c.Validate(); err != nil {
		t.Fatalf("enforce mode with self-heal on should validate: %v", err)
	}
}

func TestArmedNeverOutsideEnforce(t *testing.T) {
	// Defence in depth: even a config that bypassed Validate cannot arm anything
	// unless the mode is enforce.
	c := Default()
	c.Enforcement = Enforcement{Isolate: true, Freeze: true, SelfHeal: true, SelfProtect: true, Honeytokens: true}
	for _, m := range []mode.Mode{mode.Learn, mode.Alert} {
		c.Mode = m
		for _, f := range c.Enforcement.Requested() {
			if c.Armed(f) {
				t.Errorf("mode %s arms %s", m, f)
			}
		}
	}
}

func TestLoadRejectsNegativeReleaseAfter(t *testing.T) {
	p := writeTemp(t, "release_after: -5\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for a negative release_after")
	}
}
