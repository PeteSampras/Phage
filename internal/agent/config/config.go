// Package config holds Phage's runtime configuration and its defaults. Config
// is loaded once at startup (see internal/agent/app) and treated as immutable
// thereafter. It comes from a YAML file (see configs/phage.example.yaml) or the
// defaults. Command-line flags may tune paths and may LOWER the mode, but can
// never turn on a feature that acts on the host — those live only in the file
// (see cmd/phaged).
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	Contain float64 // at/above this score, contain (enforce mode + armed feature only)
}

// Config is the full daemon configuration.
type Config struct {
	Mode         mode.Mode
	StatePath    string // where the learned baseline is persisted
	AuditPath    string // append-only action trail; required whenever a host-modifying feature is on
	ControlPath  string // Unix socket for the phage CLI; empty disables it
	LogLevel     string
	LearnWindow  string // minimum learning duration before Alert/Enforce is advised
	Thresholds   Thresholds
	Enforcement  Enforcement // acting features; every one defaults off and needs mode enforce
	Deception    Deception   // decoys; default off, allowed in alert and enforce
	Dev          Dev         // development-only relaxations; never set in production
	ReleaseAfter int         // seconds of quiet before an isolated process is auto-released (>= 1)

	// Source identifies the file this config came from (empty when built from
	// defaults). It is reported in the startup audit record so a SIEM can tell
	// which reviewed config a host is running.
	Source Source
}

// Source is the provenance of a loaded config.
type Source struct {
	Path   string
	SHA256 string // hex sha256 of the exact bytes parsed
}

// Enforcement lists every feature that acts on processes or rewrites host
// files. Each is off by default and is honoured only when Mode is Enforce:
// Validate refuses a config that turns one on in any other mode, so an acting
// feature can never arm by accident (fail closed).
type Enforcement struct {
	Isolate     bool // network quarantine: sever a process's egress on a high egress/C2 verdict
	Freeze      bool // cgroup-freeze a process tree on a high-confidence verdict
	SelfHeal    bool // restore snapshotted sentinel files after a malicious write
	SelfProtect bool // eBPF-LSM tamper-resistance: deny signals that would kill the agent (needs BPF LSM)
}

// Deception is the decoy feature set. It creates files on the host (so it is
// opt-in and announced like enforcement) but acts on no process, so it is
// allowed in alert as well as enforce mode.
type Deception struct {
	Honeytokens bool // plant decoy credential files and alert on any read of them
}

// Dev holds relaxations that exist for running the agent by hand. None belongs
// in a production config.
type Dev struct {
	// TrustLauncherSignals lets the process that started phaged (its current
	// parent) stop it without that counting as tampering. Off: only pid 1 may.
	TrustLauncherSignals bool
}

// Feature names, as they appear in the YAML, in logs and in audit records.
const (
	FeatureIsolate     = "isolate"
	FeatureFreeze      = "freeze"
	FeatureSelfHeal    = "self_heal"
	FeatureSelfProtect = "self_protect"
	FeatureHoneytokens = "honeytokens"
)

// Requested returns the enforcement features switched on, in a stable order,
// regardless of mode.
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
	} {
		if f.on {
			out = append(out, f.name)
		}
	}
	return out
}

// HostModifying lists every requested feature that changes the host: the
// enforcement features plus honeytokens.
func (c Config) HostModifying() []string {
	out := c.Enforcement.Requested()
	if c.Deception.Honeytokens {
		out = append(out, FeatureHoneytokens)
	}
	return out
}

// Armed reports whether one host-modifying feature may arm. Enforcement
// features need mode enforce AND their own key; honeytokens need mode alert or
// enforce AND deception.honeytokens. This is the single gate every acting code
// path consults; it re-checks the mode even though Validate refuses mismatches.
func (c Config) Armed(feature string) bool {
	switch feature {
	case FeatureHoneytokens:
		return (c.Mode == mode.Alert || c.Mode == mode.Enforce) && c.Deception.Honeytokens
	}
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
	default:
		return false
	}
}

// Downgrade lowers the mode to m (an emergency override from the command line)
// and switches off every feature the lower mode does not allow, returning the
// names it switched off. It never raises the mode.
func (c *Config) Downgrade(m mode.Mode) []string {
	if m >= c.Mode {
		return nil
	}
	c.Mode = m
	var off []string
	if m != mode.Enforce {
		off = append(off, c.Enforcement.Requested()...)
		c.Enforcement = Enforcement{}
	}
	if m == mode.Learn && c.Deception.Honeytokens {
		off = append(off, FeatureHoneytokens)
		c.Deception.Honeytokens = false
	}
	return off
}

// DefaultAuditPath is where the audit trail lives unless configured otherwise.
const DefaultAuditPath = "/var/lib/phage/audit.jsonl"

// Default returns a safe starting configuration: learn-only, local state and
// audit trail, a week of learning before the baseline should be trusted,
// conservative response thresholds, and every host-modifying feature off.
func Default() Config {
	return Config{
		Mode:         mode.Learn,
		StatePath:    "/var/lib/phage/baseline.json",
		AuditPath:    DefaultAuditPath,
		ControlPath:  "/run/phage.sock",
		LogLevel:     "info",
		LearnWindow:  "168h",
		Thresholds:   Thresholds{Notify: 0.4, Contain: 0.8},
		ReleaseAfter: 300,
		// Enforcement, Deception, Dev: zero value — nothing acts.
	}
}

// strictBool accepts only the literal YAML booleans `true` and `false`. A
// feature that acts on the host must not be switched on by `yes`, `on`, `1`
// or a quoted string that some YAML dialect happens to read as true.
type strictBool bool

func (b *strictBool) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Style != 0 || (n.Value != "true" && n.Value != "false") {
		return fmt.Errorf("line %d: %q is not a literal true or false", n.Line, n.Value)
	}
	*b = n.Value == "true"
	return nil
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
		Isolate     *strictBool `yaml:"isolate"`
		Freeze      *strictBool `yaml:"freeze"`
		SelfHeal    *strictBool `yaml:"self_heal"`
		SelfProtect *strictBool `yaml:"self_protect"`
	} `yaml:"enforcement"`
	Deception *struct {
		Honeytokens *strictBool `yaml:"honeytokens"`
	} `yaml:"deception"`
	Dev *struct {
		TrustLauncherSignals *strictBool `yaml:"trust_launcher_signals"`
	} `yaml:"dev"`
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
	if err := dec.Decode(&fc); err != nil && len(bytes.TrimSpace(raw)) > 0 {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	cfg := Default()
	sum := sha256.Sum256(raw)
	cfg.Source = Source{Path: path, SHA256: hex.EncodeToString(sum[:])}
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
	}
	if d := fc.Deception; d != nil {
		setBool(&cfg.Deception.Honeytokens, d.Honeytokens)
	}
	if d := fc.Dev; d != nil {
		setBool(&cfg.Dev.TrustLauncherSignals, d.TrustLauncherSignals)
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
	if c.ReleaseAfter < 1 {
		return fmt.Errorf("release_after %d must be at least 1 second", c.ReleaseAfter)
	}
	// Fail closed: an acting feature switched on outside enforce mode is a
	// contradiction the operator must resolve, not something to quietly ignore.
	if req := c.Enforcement.Requested(); len(req) > 0 && c.Mode != mode.Enforce {
		return fmt.Errorf("enforcement feature(s) %s enabled but mode is %q: acting features arm only in mode enforce — set mode: enforce or turn them off",
			strings.Join(req, ", "), c.Mode)
	}
	if c.Deception.Honeytokens && c.Mode == mode.Learn {
		return fmt.Errorf("deception.honeytokens enabled but mode is %q: decoys are planted only in mode alert or enforce", c.Mode)
	}
	// Anything that changes the host must leave a trail.
	if hm := c.HostModifying(); len(hm) > 0 && c.AuditPath == "" {
		return fmt.Errorf("%s enabled but audit_path is empty: host-modifying features require an audit trail",
			strings.Join(hm, ", "))
	}
	return nil
}

func setString(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

func setBool(dst *bool, src *strictBool) {
	if src != nil {
		*dst = bool(*src)
	}
}
