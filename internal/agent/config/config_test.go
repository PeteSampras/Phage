package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	// The default posture is learn → alert: no host-modifying feature is on, and
	// even in enforce mode an untouched config arms nothing.
	d := Default()
	if got := d.HostModifying(); len(got) != 0 {
		t.Fatalf("Default() requests host-modifying features %v, want none", got)
	}
	for _, m := range []mode.Mode{mode.Learn, mode.Alert, mode.Enforce} {
		d.Mode = m
		for _, f := range allFeatures {
			if d.Armed(f) {
				t.Errorf("mode %s with default config arms %s", m, f)
			}
		}
	}
	if d.AuditPath != DefaultAuditPath || DefaultAuditPath == "" {
		t.Errorf("audit trail must be on by default, got %q", d.AuditPath)
	}
}

var allFeatures = []string{FeatureIsolate, FeatureFreeze, FeatureSelfHeal, FeatureSelfProtect, FeatureHoneytokens}

func TestLoadEnforcementAndDeception(t *testing.T) {
	p := writeTemp(t, `
mode: enforce
release_after: 120
enforcement:
  isolate: true
  freeze: false
  self_heal: true
  self_protect: true
deception:
  honeytokens: true
dev:
  trust_launcher_signals: true
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Enforcement{Isolate: true, SelfHeal: true, SelfProtect: true}
	if cfg.Enforcement != want {
		t.Errorf("Enforcement = %+v, want %+v", cfg.Enforcement, want)
	}
	if !cfg.Deception.Honeytokens || !cfg.Dev.TrustLauncherSignals || cfg.ReleaseAfter != 120 {
		t.Errorf("deception/dev/release_after not loaded: %+v", cfg)
	}
	if !cfg.Armed(FeatureIsolate) || cfg.Armed(FeatureFreeze) || !cfg.Armed(FeatureSelfHeal) || !cfg.Armed(FeatureHoneytokens) {
		t.Errorf("Armed() does not follow the keys: %+v", cfg)
	}
	if cfg.Source.Path != p || len(cfg.Source.SHA256) != 64 {
		t.Errorf("Source = %+v, want path and a sha256", cfg.Source)
	}
}

func TestLoadRefusesActingFeatureOutsideEnforce(t *testing.T) {
	// Fail closed: an acting feature switched on in learn or alert mode is a
	// startup error, never silently honoured (upstream ran self-heal in alert).
	for _, m := range []string{"learn", "alert"} {
		for _, key := range []string{"isolate", "freeze", "self_heal", "self_protect"} {
			p := writeTemp(t, "mode: "+m+"\nenforcement:\n  "+key+": true\n")
			if _, err := Load(p); err == nil {
				t.Errorf("mode %s with enforcement.%s: true loaded; want an error", m, key)
			}
		}
	}
}

func TestHoneytokensAllowedInAlertNotLearn(t *testing.T) {
	if _, err := Load(writeTemp(t, "mode: alert\ndeception:\n  honeytokens: true\n")); err != nil {
		t.Errorf("honeytokens in alert mode should load: %v", err)
	}
	if _, err := Load(writeTemp(t, "mode: learn\ndeception:\n  honeytokens: true\n")); err == nil {
		t.Error("honeytokens in learn mode must be refused")
	}
}

func TestHostModifyingRequiresAudit(t *testing.T) {
	for _, body := range []string{
		"mode: enforce\naudit_path: \"\"\nenforcement:\n  freeze: true\n",
		"mode: alert\naudit_path: \"\"\ndeception:\n  honeytokens: true\n",
	} {
		if _, err := Load(writeTemp(t, body)); err == nil {
			t.Errorf("host-modifying feature with no audit trail loaded:\n%s", body)
		}
	}
	if _, err := Load(writeTemp(t, "mode: alert\naudit_path: \"\"\n")); err != nil {
		t.Errorf("no features + no audit trail should load: %v", err)
	}
}

func TestStrictBooleans(t *testing.T) {
	// yes/on/1/quoted strings must never switch on a host-modifying feature.
	for _, v := range []string{"yes", "on", "1", "\"true\"", "'true'", "True", "y"} {
		p := writeTemp(t, "mode: enforce\nenforcement:\n  freeze: "+v+"\n")
		if _, err := Load(p); err == nil {
			t.Errorf("enforcement.freeze: %s accepted; only literal true/false may be", v)
		}
	}
	if c, err := Load(writeTemp(t, "mode: enforce\nenforcement:\n  freeze: false\n")); err != nil || c.Enforcement.Freeze {
		t.Errorf("literal false: cfg=%+v err=%v", c.Enforcement, err)
	}
}

func TestArmedNeverOutsideEnforce(t *testing.T) {
	// Defence in depth: even a config that bypassed Validate cannot arm an
	// enforcement feature unless the mode is enforce, or honeytokens in learn.
	c := Default()
	c.Enforcement = Enforcement{Isolate: true, Freeze: true, SelfHeal: true, SelfProtect: true}
	c.Deception.Honeytokens = true
	for _, m := range []mode.Mode{mode.Learn, mode.Alert} {
		c.Mode = m
		for _, f := range c.Enforcement.Requested() {
			if c.Armed(f) {
				t.Errorf("mode %s arms %s", m, f)
			}
		}
	}
	c.Mode = mode.Learn
	if c.Armed(FeatureHoneytokens) {
		t.Error("learn mode arms honeytokens")
	}
}

func TestDowngrade(t *testing.T) {
	c := Default()
	c.Mode = mode.Enforce
	c.Enforcement = Enforcement{Freeze: true, SelfHeal: true}
	c.Deception.Honeytokens = true
	off := c.Downgrade(mode.Alert)
	if c.Mode != mode.Alert || len(c.Enforcement.Requested()) != 0 || !c.Deception.Honeytokens {
		t.Errorf("downgrade to alert: %+v", c)
	}
	if len(off) != 2 {
		t.Errorf("disarmed = %v, want freeze,self_heal", off)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("downgraded config must validate: %v", err)
	}
	if off := c.Downgrade(mode.Learn); len(off) != 1 || c.Deception.Honeytokens {
		t.Errorf("downgrade to learn should switch off honeytokens: %v %+v", off, c.Deception)
	}
	if off := c.Downgrade(mode.Enforce); off != nil || c.Mode != mode.Learn {
		t.Error("Downgrade must never raise the mode")
	}
}

func TestLoadRejectsBadReleaseAfter(t *testing.T) {
	for _, v := range []string{"-5", "0"} {
		if _, err := Load(writeTemp(t, "release_after: "+v+"\n")); err == nil {
			t.Errorf("release_after: %s accepted", v)
		}
	}
}

func TestOutputAndLearnDefaults(t *testing.T) {
	c := Default()
	o := c.Output
	if o.NoveltyPath != "" || o.Source != "phage-host" || o.EntityKind != "" || o.Entity != "" || o.TLP != "" ||
		o.HeartbeatInterval != 60 || o.NoveltyBucket != time.Hour || o.NoveltyMaxPerBucket != 20 {
		t.Errorf("output defaults = %+v (the sink is opt-in: no path, no label, no entity)", o)
	}
	if c.Learn.CheckpointInterval != 10*time.Minute || c.Learn.MaxValuesPerKey != 10000 || c.Learn.MinBaselineSamples != 5000 {
		t.Errorf("learn defaults = %+v", c.Learn)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if len(c.HostModifying()) != 0 {
		t.Fatal("the output block must not arm anything")
	}
}

const sinkOn = "output:\n  novelty_path: /tmp/n.jsonl\n"

func TestLoadOutputAndLearn(t *testing.T) {
	p := writeTemp(t, `
mode: alert
output:
  novelty_path: /tmp/n.jsonl
  novelty_max_bytes: 0
  novelty_bucket: 30m
  novelty_max_per_bucket: 5
  source: phage-canary
  entity_kind: ip
  entity: 192.0.2.10
  tlp: amber+strict
  heartbeat_interval: 30
learn:
  checkpoint_interval: 5m
  max_values_per_key: 50
  min_baseline_samples: 100
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := Output{NoveltyPath: "/tmp/n.jsonl", NoveltyBucket: 30 * time.Minute, Source: "phage-canary",
		EntityKind: "ip", Entity: "192.0.2.10", TLP: "amber+strict", HeartbeatInterval: 30, NoveltyMaxPerBucket: 5}
	if c.Output != want {
		t.Errorf("output = %+v, want %+v", c.Output, want)
	}
	if c.Learn != (Learn{CheckpointInterval: 5 * time.Minute, MaxValuesPerKey: 50, MinBaselineSamples: 100}) {
		t.Errorf("learn = %+v", c.Learn)
	}
}

func TestOutputRefusals(t *testing.T) {
	full := sinkOn + "  entity_kind: host\n  entity: web01\n"
	for name, body := range map[string]string{
		"sink without tlp":    sinkOn + "  entity_kind: host\n  entity: web01\n",
		"sink without entity": sinkOn + "  tlp: amber\n",
		"sink without kind":   sinkOn + "  tlp: amber\n  entity: web01\n",
		"tlp red":             full + "  tlp: red\n",
		"tlp prefixed":        full + "  tlp: TLP:AMBER\n",
		"tlp upper case":      full + "  tlp: AMBER\n",
		"tlp v1 white":        full + "  tlp: white\n",
		"tlp red, sink off":   "output:\n  tlp: red\n",
		"host upper case":     sinkOn + "  tlp: amber\n  entity_kind: host\n  entity: Web01\n",
		"source with space":   "output:\n  source: phage host\n",
		"source upper":        "output:\n  source: Phage\n",
		"source lake":         "output:\n  source: lake-novelty\n",
		"source too long":     "output:\n  source: " + strings.Repeat("a", 65) + "\n",
		"unknown kind":        "output:\n  entity_kind: vm\n  entity: x\n",
		"ip without entity":   "output:\n  entity_kind: ip\n",
		"ip not an address":   "output:\n  entity_kind: ip\n  entity: web01\n",
		"ip not canonical":    "output:\n  entity_kind: ip\n  entity: \"2001:DB8::1\"\n",
		"entity with space":   "output:\n  entity_kind: host\n  entity: \"web 01\"\n",
		"tiny rotation":       "output:\n  novelty_max_bytes: 1000\n",
		"bucket too small":    "output:\n  novelty_bucket: 10s\n",
		"bucket not duration": "output:\n  novelty_bucket: hourly\n",
		"per-bucket zero":     "output:\n  novelty_max_per_bucket: 0\n",
		"heartbeat zero":      "output:\n  heartbeat_interval: 0\n",
		"unknown output key":  "output:\n  novelty: true\n",
		"checkpoint tiny":     "learn:\n  checkpoint_interval: 1s\n",
		"checkpoint bad":      "learn:\n  checkpoint_interval: often\n",
		"cap zero":            "learn:\n  max_values_per_key: 0\n",
	} {
		if _, err := Load(writeTemp(t, body)); err == nil {
			t.Errorf("%s: accepted %q", name, body)
		}
	}
	for _, l := range []string{"clear", "green", "amber", "amber+strict"} {
		if _, err := Load(writeTemp(t, full+"  tlp: "+l+"\n")); err != nil {
			t.Errorf("tlp %q refused: %v", l, err)
		}
	}
	if _, err := Load(writeTemp(t, sinkOn+"  tlp: amber\n  entity_kind: ip\n  entity: \"2001:db8::1\"\n")); err != nil {
		t.Errorf("canonical v6 refused: %v", err)
	}
	_, err := Load(writeTemp(t, full+"  tlp: red\n"))
	if err == nil || !strings.Contains(err.Error(), "never be written to the lake") {
		t.Errorf("red must be refused with the reason, got %v", err)
	}
}
