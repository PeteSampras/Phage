// Package config holds Phage's runtime configuration and its defaults. Config
// is loaded once at startup (see internal/agent/app) and treated as immutable
// thereafter. It can come from a YAML file (see configs/phage.example.yaml),
// from defaults, or a mix — the daemon overlays explicit command-line flags on
// top so an operator can tune one knob without editing a file.
package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"gopkg.in/yaml.v3"
)

// Thresholds map an anomaly score (0.0 normal .. 1.0 certainly anomalous) to a
// response intent. Tuning aggressiveness lives here, as data, not in code.
type Thresholds struct {
	Notify  float64 // at/above this score, raise an alert
	Contain float64 // at/above this score, contain (enforce mode only)
}

// Config is the full daemon configuration.
type Config struct {
	Mode         mode.Mode
	StatePath    string // where the learned baseline is persisted
	AuditPath    string // append-only action trail; empty disables auditing
	ControlPath  string // Unix socket for the phage CLI; empty disables it
	LogLevel     string
	LearnWindow  string // minimum learning duration before Alert/Enforce is advised
	Thresholds   Thresholds
	Enforcement  Enforcement // acting features; every one defaults off and needs mode enforce
	ReleaseAfter int         // seconds of quiet before an isolated process is auto-released (de-escalation); 0 = default 300
}

// Enforcement lists every feature that changes the host rather than only
// reporting on it. Each is off by default and is honoured only when Mode is
// Enforce: Validate refuses a config that turns one on in any other mode, so an
// acting feature can never arm by accident (fail closed). Detection, scoring and
// alerting need none of these.
type Enforcement struct {
	Isolate     bool // network quarantine: sever a process's egress on a high egress/C2 verdict
	Freeze      bool // cgroup-freeze a process tree on a high-confidence verdict
	SelfHeal    bool // restore snapshotted sentinel files after a malicious write
	SelfProtect bool // eBPF-LSM tamper-resistance: deny signals that would kill the agent (needs BPF LSM)
	Honeytokens bool // plant decoy credential files (and alert on any read of them)
}

// Feature names, as they appear in the YAML `enforcement:` block, in logs and in
// the enforcement_armed audit record.
const (
	FeatureIsolate     = "isolate"
	FeatureFreeze      = "freeze"
	FeatureSelfHeal    = "self_heal"
	FeatureSelfProtect = "self_protect"
	FeatureHoneytokens = "honeytokens"
)

// Requested returns the names of the acting features switched on in this
// config, in a stable order, regardless of mode.
func (e Enforcement) Requested() []string {
	var out []string
	for _, f := range []struct {
		on   bool
		name string
	}{
		{e.Isolate, FeatureIsolate},
		{e.Freeze, FeatureFreeze},
		{e.SelfHeal, FeatureSelfHeal},
		{e.SelfProtect, FeatureSelfProtect},
		{e.Honeytokens, FeatureHoneytokens},
	} {
		if f.on {
			out = append(out, f.name)
		}
	}
	return out
}

// Armed reports whether one acting feature may arm: its own key is on AND the
// mode is enforce. This is the single gate every acting code path consults; it
// is checked again at use even though Validate already refuses the mismatch.
func (c Config) Armed(feature string) bool {
	if c.Mode != mode.Enforce {
		return false
	}
	switch feature {
	case FeatureIsolate:
		return c.Enforcement.Isolate
	case FeatureFreeze:
		return c.Enforcement.Freeze
	case FeatureSelfHeal:
		return c.Enforcement.SelfHeal
	case FeatureSelfProtect:
		return c.Enforcement.SelfProtect
	case FeatureHoneytokens:
		return c.Enforcement.Honeytokens
	default:
		return false
	}
}

// Default returns a safe starting configuration: learn-only, local state, a
// week of learning before the baseline should be trusted, conservative
// response thresholds, and every acting feature off.
func Default() Config {
	return Config{
		Mode:        mode.Learn,
		StatePath:   "/var/lib/phage/baseline.json",
		AuditPath:   "",
		ControlPath: "/run/phage.sock",
		LogLevel:    "info",
		LearnWindow: "168h",
		Thresholds:  Thresholds{Notify: 0.4, Contain: 0.8},
		// Enforcement: zero value — nothing acts unless the operator turns it on.
		ReleaseAfter: 300,
	}
}

// fileConfig mirrors the YAML on disk. Every field is a pointer so Load can tell
// "absent, keep the default" from "present and set to the zero value" — which
// matters for a threshold an operator deliberately sets to 0.
type fileConfig struct {
	Mode        *string `yaml:"mode"`
	StatePath   *string `yaml:"state_path"`
	AuditPath   *string `yaml:"audit_path"`
	ControlPath *string `yaml:"control_path"`
	LogLevel    *string `yaml:"log_level"`
	LearnWindow *string `yaml:"learn_window"`
	Thresholds  *struct {
		Notify  *float64 `yaml:"notify"`
		Contain *float64 `yaml:"contain"`
	} `yaml:"thresholds"`
	Enforcement *struct {
		Isolate     *bool `yaml:"isolate"`
		Freeze      *bool `yaml:"freeze"`
		SelfHeal    *bool `yaml:"self_heal"`
		SelfProtect *bool `yaml:"self_protect"`
		Honeytokens *bool `yaml:"honeytokens"`
	} `yaml:"enforcement"`
	ReleaseAfter *int `yaml:"release_after"`
}

// Load reads a YAML config file, overlays it on Default(), and validates the
// result. Fields absent from the file keep their default. A malformed file or
// an invalid combination (see Validate) is an error, never a silent fallback —
// a security daemon must not start with a config the operator did not mean.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // reject unknown keys: a typo'd threshold must fail loudly
	if err := dec.Decode(&fc); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	cfg := Default()
	if fc.Mode != nil {
		m, err := mode.Parse(*fc.Mode)
		if err != nil {
			return Config{}, fmt.Errorf("config %q: %w", path, err)
		}
		cfg.Mode = m
	}
	setString(&cfg.StatePath, fc.StatePath)
	setString(&cfg.AuditPath, fc.AuditPath)
	setString(&cfg.ControlPath, fc.ControlPath)
	setString(&cfg.LogLevel, fc.LogLevel)
	setString(&cfg.LearnWindow, fc.LearnWindow)
	if fc.Thresholds != nil {
		if fc.Thresholds.Notify != nil {
			cfg.Thresholds.Notify = *fc.Thresholds.Notify
		}
		if fc.Thresholds.Contain != nil {
			cfg.Thresholds.Contain = *fc.Thresholds.Contain
		}
	}
	if e := fc.Enforcement; e != nil {
		setBool(&cfg.Enforcement.Isolate, e.Isolate)
		setBool(&cfg.Enforcement.Freeze, e.Freeze)
		setBool(&cfg.Enforcement.SelfHeal, e.SelfHeal)
		setBool(&cfg.Enforcement.SelfProtect, e.SelfProtect)
		setBool(&cfg.Enforcement.Honeytokens, e.Honeytokens)
	}
	if fc.ReleaseAfter != nil {
		cfg.ReleaseAfter = *fc.ReleaseAfter
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects a configuration that cannot behave sanely. It is the one
// gate every config passes through, whether it came from a file or flags.
func (c Config) Validate() error {
	n, co := c.Thresholds.Notify, c.Thresholds.Contain
	if n < 0 || n > 1 {
		return fmt.Errorf("notify threshold %.2f out of range [0,1]", n)
	}
	if co < 0 || co > 1 {
		return fmt.Errorf("contain threshold %.2f out of range [0,1]", co)
	}
	if n > co {
		return fmt.Errorf("notify threshold %.2f must not exceed contain threshold %.2f", n, co)
	}
	if c.ReleaseAfter < 0 {
		return fmt.Errorf("release_after %d must not be negative", c.ReleaseAfter)
	}
	// Fail closed: an acting feature switched on outside enforce mode is a
	// contradiction the operator must resolve, not something to quietly ignore
	// (or quietly honour, as upstream did for -heal/-protect/-honeytokens).
	if req := c.Enforcement.Requested(); len(req) > 0 && c.Mode != mode.Enforce {
		return fmt.Errorf("enforcement feature(s) %s enabled but mode is %q: acting features arm only in mode enforce — set mode: enforce or turn them off",
			strings.Join(req, ", "), c.Mode)
	}
	return nil
}

func setString(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

func setBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}
