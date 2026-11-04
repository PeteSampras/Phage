// Command phaged is the Phage daemon: it loads the eBPF sensors, runs the
// analysis pipeline, and applies responses according to the configured mode.
//
// This entrypoint is intentionally thin — all wiring lives in
// internal/agent/app. The eBPF sensors load on Linux only (see internal/sensor
// and docs/guides/development.md); on other platforms Load fails cleanly.
package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/AzozzALFiras/Phage/internal/agent/app"
	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/store/backend/jsonfile"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	defaults := config.Default()

	configPath := flag.String("config", "", "path to a YAML config file (see configs/phage.example.yaml)")
	bpfPath := flag.String("bpf", "bpf/build/sensors.bpf.o", "path to the compiled eBPF object")
	statePath := flag.String("state", defaults.StatePath, "path to the learned baseline file")
	auditPath := flag.String("audit", defaults.AuditPath, "append-only action audit log (empty disables)")
	controlPath := flag.String("control", defaults.ControlPath, "control socket for the phage CLI (empty disables)")
	modeName := flag.String("mode", defaults.Mode.String(), "operating mode: learn | alert | enforce")
	// The acting-feature flags mirror the YAML `enforcement:` keys. They are
	// accepted only together with mode enforce: phaged refuses to start if one is
	// set in learn or alert mode (fail closed). Prefer the config file.
	protect := flag.Bool("protect", false, "same as enforcement.self_protect: eBPF-LSM tamper-resistance, deny signals that would kill the agent (REQUIRES mode enforce; needs BPF LSM; systemctl/reboot still stop it)")
	honeytokens := flag.Bool("honeytokens", false, "same as enforcement.honeytokens: plant decoy credential files; any read of one is a high-confidence intrusion alert (REQUIRES mode enforce)")
	heal := flag.Bool("heal", false, "same as enforcement.self_heal: restore sentinel files (authorized_keys/cron/...) after a malicious write, keeping the attacker's version as evidence (REQUIRES mode enforce)")
	releaseAfter := flag.Int("release-after", defaults.ReleaseAfter, "same as release_after: seconds of quiet before an isolated process is automatically released (graduated de-escalation)")
	flag.Parse()

	// Base config: the file if given (validated on load), else the defaults.
	cfg := defaults
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("phaged: %v", err)
		}
		cfg = loaded
	}

	// Explicitly-set flags override the file, so an operator can tune one knob
	// without editing it. Flags left at their default never clobber file values.
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["mode"] {
		m, err := mode.Parse(*modeName)
		if err != nil {
			log.Fatalf("phaged: %v", err)
		}
		cfg.Mode = m
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
	if set["protect"] {
		cfg.Enforcement.SelfProtect = *protect
	}
	if set["honeytokens"] {
		cfg.Enforcement.Honeytokens = *honeytokens
	}
	if set["heal"] {
		cfg.Enforcement.SelfHeal = *heal
	}
	if set["release-after"] {
		cfg.ReleaseAfter = *releaseAfter
	}
	// Validate is where the fail-closed rule lives: any acting feature requested
	// (from the file or a flag) outside mode enforce is a startup error.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("phaged: %v", err)
	}

	log.Printf("phaged %s starting in %q mode (state %s; notify=%.2f contain=%.2f)",
		version, cfg.Mode, cfg.StatePath, cfg.Thresholds.Notify, cfg.Thresholds.Contain)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := jsonfile.New(cfg.StatePath)
	if err := app.New(cfg, *bpfPath, store).Run(ctx); err != nil {
		log.Fatalf("phaged: %v", err)
	}
	log.Printf("phaged stopped")
}
