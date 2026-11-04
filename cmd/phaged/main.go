// Command phaged is the Phage daemon: it loads the eBPF sensors, runs the
// analysis pipeline, and applies responses according to the configured mode.
//
// This entrypoint is intentionally thin — all wiring lives in
// internal/agent/app. The eBPF sensors load on Linux only (see internal/sensor
// and docs/guides/development.md); on other platforms Load fails cleanly.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/AzozzALFiras/Phage/internal/agent/app"
	"github.com/AzozzALFiras/Phage/internal/store/backend/jsonfile"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	opt, err := parseOptions(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		log.Fatalf("phaged: %v", err)
	}
	cfg := opt.cfg

	log.Printf("phaged %s starting in %q mode (state %s; notify=%.2f contain=%.2f)",
		version, cfg.Mode, cfg.StatePath, cfg.Thresholds.Notify, cfg.Thresholds.Contain)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := jsonfile.New(cfg.StatePath)
	meta := app.Meta{Version: version, Disarmed: opt.disarmed, DowngradedFrom: opt.fromMode}
	if err := app.New(cfg, opt.bpfPath, store, meta).Run(ctx); err != nil {
		log.Fatalf("phaged: %v", err)
	}
	log.Printf("phaged stopped")
}
