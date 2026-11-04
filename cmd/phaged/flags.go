package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
)

// options is everything phaged takes from its command line.
type options struct {
	cfg      config.Config
	bpfPath  string
	disarmed []string  // features a -mode downgrade switched off
	fromMode mode.Mode // the config file's mode before a downgrade
}

// movedFlags are the old CLI switches for host-modifying features. They are
// still recognised so that using one fails with a pointer to the config key,
// rather than "flag provided but not defined".
var movedFlags = map[string]string{
	"heal":        "enforcement.self_heal",
	"protect":     "enforcement.self_protect",
	"honeytokens": "deception.honeytokens",
}

// parseOptions turns phaged's arguments into a validated config. The rules:
//   - no flag can arm a host-modifying feature: -heal/-protect/-honeytokens are
//     errors that name the config key that replaced them;
//   - -mode may only LOWER the config file's mode, never raise it; lowering
//     switches off whatever the lower mode does not allow (an emergency
//     downgrade starts disarmed rather than refusing to start);
//   - without -config, -mode enforce is refused (enforcement is configured in
//     the file and only there).
func parseOptions(args []string, stderr io.Writer) (options, error) {
	defaults := config.Default()
	fs := flag.NewFlagSet("phaged", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the YAML config file (see configs/phage.example.yaml); the only place host-modifying features can be enabled")
	bpfPath := fs.String("bpf", "bpf/build/sensors.bpf.o", "path to the compiled eBPF object")
	statePath := fs.String("state", defaults.StatePath, "path to the learned baseline file")
	auditPath := fs.String("audit", defaults.AuditPath, "append-only audit trail (required when any host-modifying feature is on)")
	controlPath := fs.String("control", defaults.ControlPath, "control socket for the phage CLI (empty disables)")
	modeName := fs.String("mode", defaults.Mode.String(), "operating mode: learn | alert | enforce — may only LOWER the config file's mode (emergency downgrade); enforce needs -config")
	releaseAfter := fs.Int("release-after", defaults.ReleaseAfter, "seconds of quiet before an isolated process is automatically released (>= 1)")
	for name, key := range movedFlags {
		fs.Bool(name, false, "REMOVED: set "+key+" in the config file")
	}
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, name := range []string{"heal", "protect", "honeytokens"} {
		if set[name] {
			return options{}, fmt.Errorf("-%s has moved to %s in the config file; flags can no longer enable host-modifying features", name, movedFlags[name])
		}
	}

	cfg := defaults
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			return options{}, err
		}
		cfg = loaded
	}

	opt := options{bpfPath: *bpfPath, fromMode: cfg.Mode}
	if set["mode"] {
		m, err := mode.Parse(*modeName)
		if err != nil {
			return options{}, err
		}
		switch {
		case *configPath == "" && m == mode.Enforce:
			return options{}, errors.New("-mode enforce requires -config: enforcement is configured in the config file only")
		case *configPath == "" && m > cfg.Mode:
			cfg.Mode = m // no file: defaults are learn; alert is allowed for a hand run
		case m > cfg.Mode:
			return options{}, fmt.Errorf("-mode %s would raise the config file's mode %s; flags may only lower it", m, cfg.Mode)
		default:
			opt.disarmed = cfg.Downgrade(m)
		}
	}
	if set["state"] {
		cfg.StatePath = *statePath
	}
	if set["audit"] {
		cfg.AuditPath = *auditPath
	}
	if set["control"] {
		cfg.ControlPath = *controlPath
	}
	if set["release-after"] {
		cfg.ReleaseAfter = *releaseAfter
	}
	if err := cfg.Validate(); err != nil {
		return options{}, err
	}
	opt.cfg = cfg
	return opt, nil
}
