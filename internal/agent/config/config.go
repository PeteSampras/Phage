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
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

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
	Output       Output      // novelty sink and health heartbeat (observability only; acts on nothing)
	Learn        Learn       // baseline checkpointing and growth bounds

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

// Output configures what phaged reports for other systems to read. Nothing in
// it acts on the host: it only writes files phaged owns.
type Output struct {
	// NoveltyPath (opt-in; empty by default) is the JSON-lines file that receives one novelty_finding row
	// (homelab-next ADR-0036) per verdict at or above the notify threshold, and
	// one `unlearned` row when an event's feature class has no baseline. Written
	// only in alert and enforce mode. Empty disables it.
	NoveltyPath string
	// NoveltyMaxBytes rotates the file to NoveltyPath+".1" once it would grow
	// past this size. 0 never rotates (use logrotate copytruncate instead).
	NoveltyMaxBytes int64
	// NoveltyBucket is the time bucket in a row's uid: the same finding (same
	// profile, entity, value and status) within one bucket has one uid, and
	// phaged writes it once per bucket.
	NoveltyBucket time.Duration
	// Source names this sensor in the row's `source` column.
	Source string
	// EntityKind and Entity name the host in the shared entity namespace
	// (ADR-0036 decision 7), as the lake's profiles name it. Both are required
	// when NoveltyPath is set; there is no default (a host name rarely matches
	// what a lake profile uses).
	EntityKind string
	Entity     string
	// TLP is the TLP 2.0 label every row carries. Required when NoveltyPath is
	// set; one of the canonical lower-case labels except red (a red row can
	// never be written to the lake: its writers read below red).
	TLP string
	// NoveltyMaxPerBucket caps the new rows one profile may write in one uid
	// bucket; past it, one `burst` row with the count stands for the rest.
	NoveltyMaxPerBucket int
	// HeartbeatInterval is the number of seconds between `heartbeat` audit
	// records (sensor health), written in every mode.
	HeartbeatInterval int
}

// Learn bounds the learned baseline.
type Learn struct {
	// CheckpointInterval is how often learn mode saves the baseline (atomic
	// temp file + rename) while running, so a crash loses at most one interval.
	CheckpointInterval time.Duration
	// MinBaselineSamples is the total feature observations below which the
	// baseline is `warming` (0: `no_baseline`). Until it is reached, events of
	// a never-seen feature class are not reported as unlearned.
	MinBaselineSamples uint64
	// MaxValuesPerKey caps the distinct values one feature key may learn; a new
	// value past the cap is counted as overflow and not learned.
	MaxValuesPerKey int
}

// Novelty-row vocabularies (homelab-next schemas/ocsf/novelty_finding.v1.json).
var (
	// TLPLabels are the canonical TLP 2.0 labels, exactly as the lake stores them.
	TLPLabels = []string{"clear", "green", "amber", "amber+strict", "red"}
	// EntityKinds is the shared entity namespace.
	EntityKinds = []string{"ip", "host", "user", "domain", "process", "other"}
	// sourcePattern is the schema's pattern for `source` (and `profile`).
	sourcePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
)

// Defaults for the output and learn blocks.
const (
	// DefaultNoveltyPath is the conventional path for the opt-in sink.
	DefaultNoveltyPath     = "/var/lib/phage/novelty.jsonl"
	DefaultNoveltyMaxBytes = 64 << 20
	DefaultSource          = "phage-host"
	// lakeSource is the lake analyzer's own source; a host sensor must not
	// write under it (corroborate counts distinct sources).
	lakeSource = "lake-novelty"
)

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
		Output: Output{
			NoveltyMaxPerBucket: 20,
			NoveltyMaxBytes:     DefaultNoveltyMaxBytes,
			NoveltyBucket:       time.Hour,
			Source:              DefaultSource,
			HeartbeatInterval:   60,
		},
		Learn: Learn{CheckpointInterval: 10 * time.Minute, MaxValuesPerKey: 10000, MinBaselineSamples: 5000},
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
	Output       *struct {
		NoveltyPath         *string `yaml:"novelty_path"`
		NoveltyMaxBytes     *int64  `yaml:"novelty_max_bytes"`
		NoveltyBucket       *string `yaml:"novelty_bucket"`
		Source              *string `yaml:"source"`
		EntityKind          *string `yaml:"entity_kind"`
		Entity              *string `yaml:"entity"`
		TLP                 *string `yaml:"tlp"`
		NoveltyMaxPerBucket *int    `yaml:"novelty_max_per_bucket"`
		HeartbeatInterval   *int    `yaml:"heartbeat_interval"`
	} `yaml:"output"`
	Learn *struct {
		CheckpointInterval *string `yaml:"checkpoint_interval"`
		MaxValuesPerKey    *int    `yaml:"max_values_per_key"`
		MinBaselineSamples *uint64 `yaml:"min_baseline_samples"`
	} `yaml:"learn"`
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
	if o := fc.Output; o != nil {
		setString(&cfg.Output.NoveltyPath, o.NoveltyPath)
		if o.NoveltyMaxBytes != nil {
			cfg.Output.NoveltyMaxBytes = *o.NoveltyMaxBytes
		}
		if err := setDuration(&cfg.Output.NoveltyBucket, o.NoveltyBucket); err != nil {
			return Config{}, fmt.Errorf("config %q: output.novelty_bucket: %w", path, err)
		}
		setString(&cfg.Output.Source, o.Source)
		setString(&cfg.Output.EntityKind, o.EntityKind)
		setString(&cfg.Output.Entity, o.Entity)
		setString(&cfg.Output.TLP, o.TLP)
		if o.NoveltyMaxPerBucket != nil {
			cfg.Output.NoveltyMaxPerBucket = *o.NoveltyMaxPerBucket
		}
		if o.HeartbeatInterval != nil {
			cfg.Output.HeartbeatInterval = *o.HeartbeatInterval
		}
	}
	if l := fc.Learn; l != nil {
		if err := setDuration(&cfg.Learn.CheckpointInterval, l.CheckpointInterval); err != nil {
			return Config{}, fmt.Errorf("config %q: learn.checkpoint_interval: %w", path, err)
		}
		if l.MinBaselineSamples != nil {
			cfg.Learn.MinBaselineSamples = *l.MinBaselineSamples
		}
		if l.MaxValuesPerKey != nil {
			cfg.Learn.MaxValuesPerKey = *l.MaxValuesPerKey
		}
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
	if err := c.Output.validate(); err != nil {
		return err
	}
	if err := c.Learn.validate(); err != nil {
		return err
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

func (o Output) validate() error {
	if len(o.Source) > 64 || !sourcePattern.MatchString(o.Source) {
		return fmt.Errorf("output.source %q must be lower-case words joined by single hyphens (at most 64 characters)", o.Source)
	}
	if o.Source == lakeSource {
		return fmt.Errorf("output.source %q is the lake analyzer's own source; a host sensor needs its own", o.Source)
	}
	// TLP and entity are checked whenever given, and required with the sink.
	if o.TLP != "" || o.NoveltyPath != "" {
		if err := ValidateTLP(o.TLP); err != nil {
			return err
		}
	}
	if o.EntityKind != "" || o.Entity != "" || o.NoveltyPath != "" {
		if !contains(EntityKinds, o.EntityKind) {
			return fmt.Errorf("output.entity_kind %q must be one of %s (required with output.novelty_path)", o.EntityKind, strings.Join(EntityKinds, ", "))
		}
		if err := ValidateEntity(o.EntityKind, o.Entity); err != nil {
			return err
		}
	}
	if o.NoveltyMaxPerBucket < 1 || o.NoveltyMaxPerBucket > 100000 {
		return fmt.Errorf("output.novelty_max_per_bucket %d must be between 1 and 100000", o.NoveltyMaxPerBucket)
	}
	if o.NoveltyMaxBytes != 0 && o.NoveltyMaxBytes < 1<<20 {
		return fmt.Errorf("output.novelty_max_bytes %d must be 0 (never rotate) or at least 1048576", o.NoveltyMaxBytes)
	}
	if o.NoveltyBucket < time.Minute || o.NoveltyBucket > 24*time.Hour {
		return fmt.Errorf("output.novelty_bucket %s must be between 1m and 24h", o.NoveltyBucket)
	}
	if o.HeartbeatInterval < 5 || o.HeartbeatInterval > 3600 {
		return fmt.Errorf("output.heartbeat_interval %d must be between 5 and 3600 seconds", o.HeartbeatInterval)
	}
	return nil
}

// ValidateTLP accepts the labels a novelty row may carry: the canonical TLP
// 2.0 labels, lower case, except red. A red row cannot reach the lake: the
// lake's analyzer-output writers read below red (homelab-next ADR-0036), and
// rows that can never be written must not be produced. There is no default.
func ValidateTLP(l string) error {
	if l == "" {
		return fmt.Errorf("output.tlp is required with output.novelty_path: one of clear, green, amber, amber+strict")
	}
	if l == "red" {
		return fmt.Errorf("output.tlp red is refused: a red novelty row can never be written to the lake (its writers read below red); use amber+strict or lower")
	}
	if !contains(TLPLabels, l) {
		return fmt.Errorf("output.tlp %q is not a TLP 2.0 label: use one of clear, green, amber, amber+strict, exactly (lower case, no TLP: prefix)", l)
	}
	return nil
}

// ValidateEntity checks an entity's text for its kind: required, at most 512
// bytes, no spaces or control characters, a host name in lower case. An ip must be written in canonical form (as netip prints it), the
// form a lake profile holds, so both sources name one entity identically.
func ValidateEntity(kind, entity string) error {
	if entity == "" {
		return fmt.Errorf("output.entity is required when output.entity_kind is %q", kind)
	}
	if len(entity) > 512 {
		return fmt.Errorf("output.entity is %d bytes; at most 512", len(entity))
	}
	for _, r := range entity {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("output.entity %q must not contain spaces or control characters", entity)
		}
	}
	if kind == "host" && strings.ToLower(entity) != entity {
		return fmt.Errorf("output.entity %q: write a host name in lower case (%q), as the lake does", entity, strings.ToLower(entity))
	}
	if kind == "ip" {
		a, err := netip.ParseAddr(entity)
		if err != nil {
			return fmt.Errorf("output.entity %q is not an IP address: %w", entity, err)
		}
		if a.String() != entity {
			return fmt.Errorf("output.entity %q is not in canonical form; write %q", entity, a.String())
		}
	}
	return nil
}

func (l Learn) validate() error {
	if l.CheckpointInterval < 10*time.Second || l.CheckpointInterval > 24*time.Hour {
		return fmt.Errorf("learn.checkpoint_interval %s must be between 10s and 24h", l.CheckpointInterval)
	}
	if l.MaxValuesPerKey < 1 {
		return fmt.Errorf("learn.max_values_per_key %d must be at least 1", l.MaxValuesPerKey)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func setDuration(dst *time.Duration, src *string) error {
	if src == nil {
		return nil
	}
	d, err := time.ParseDuration(*src)
	if err != nil {
		return err
	}
	*dst = d
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
