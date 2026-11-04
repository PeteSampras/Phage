package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/policy/mode"
)

func cfgFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "phage.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const enforceArmed = "mode: enforce\nenforcement:\n  freeze: true\n  self_heal: true\ndeception:\n  honeytokens: true\n"

func TestMovedFlagsAreErrors(t *testing.T) {
	p := cfgFile(t, enforceArmed)
	for flag, key := range movedFlags {
		for _, args := range [][]string{
			{"-" + flag},
			{"-" + flag + "=false"},
			{"-config", p, "-" + flag},
		} {
			_, err := parseOptions(args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("%v: err = %v, want an error naming %s", args, err, key)
			}
		}
	}
}

func TestModeMayNotRaiseTheFile(t *testing.T) {
	p := cfgFile(t, "mode: alert\n")
	if _, err := parseOptions([]string{"-config", p, "-mode", "enforce"}, io.Discard); err == nil {
		t.Error("-mode enforce over an alert config must be refused")
	}
	p = cfgFile(t, "mode: learn\n")
	if _, err := parseOptions([]string{"-config", p, "-mode", "alert"}, io.Discard); err == nil {
		t.Error("-mode alert over a learn config must be refused")
	}
}

// Without -config the mode is the default (learn); -mode may never raise it,
// so only -mode learn is accepted.
func TestModeWithoutConfigNeverRaises(t *testing.T) {
	for _, m := range []string{"enforce", "alert"} {
		if _, err := parseOptions([]string{"-mode", m}, io.Discard); err == nil {
			t.Errorf("-mode %s without -config must be refused", m)
		}
	}
	opt, err := parseOptions([]string{"-mode", "learn"}, io.Discard)
	if err != nil || opt.cfg.Mode != mode.Learn || len(opt.cfg.HostModifying()) != 0 {
		t.Errorf("-mode learn without -config should run, arming nothing: %v", err)
	}
}

func TestEmergencyDowngradeStartsDisarmed(t *testing.T) {
	p := cfgFile(t, enforceArmed)
	opt, err := parseOptions([]string{"-config", p, "-mode", "alert"}, io.Discard)
	if err != nil {
		t.Fatalf("downgrade must not fail (no crash-loop): %v", err)
	}
	if opt.cfg.Mode != mode.Alert || len(opt.cfg.Enforcement.Requested()) != 0 {
		t.Errorf("downgrade left enforcement on: %+v", opt.cfg.Enforcement)
	}
	if !opt.cfg.Deception.Honeytokens {
		t.Error("honeytokens are allowed in alert and should survive a downgrade to alert")
	}
	if got := strings.Join(opt.disarmed, ","); got != "freeze,self_heal" || opt.fromMode != mode.Enforce {
		t.Errorf("disarmed=%q from=%s", got, opt.fromMode)
	}

	opt, err = parseOptions([]string{"-config", p, "-mode", "learn"}, io.Discard)
	if err != nil || len(opt.cfg.HostModifying()) != 0 || len(opt.disarmed) != 3 {
		t.Errorf("downgrade to learn: err=%v cfg=%+v disarmed=%v", err, opt.cfg, opt.disarmed)
	}
}

func TestSameModeIsNoDowngrade(t *testing.T) {
	p := cfgFile(t, enforceArmed)
	opt, err := parseOptions([]string{"-config", p, "-mode", "enforce"}, io.Discard)
	if err != nil || len(opt.disarmed) != 0 || !opt.cfg.Enforcement.Freeze {
		t.Errorf("-mode equal to the file's: err=%v disarmed=%v", err, opt.disarmed)
	}
}

func TestPathFlagsStillOverride(t *testing.T) {
	p := cfgFile(t, "mode: alert\n")
	opt, err := parseOptions([]string{"-config", p, "-state", "/x/b.json", "-control", "", "-release-after", "60"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if opt.cfg.StatePath != "/x/b.json" || opt.cfg.ControlPath != "" || opt.cfg.ReleaseAfter != 60 {
		t.Errorf("overrides not applied: %+v", opt.cfg)
	}
	if _, err := parseOptions([]string{"-config", p, "-release-after", "0"}, io.Discard); err == nil {
		t.Error("-release-after 0 must be refused")
	}
}

func TestAuditFlagCannotDropTrailUnderFeatures(t *testing.T) {
	p := cfgFile(t, enforceArmed)
	if _, err := parseOptions([]string{"-config", p, "-audit", ""}, io.Discard); err == nil {
		t.Error("-audit \"\" with host-modifying features on must be refused")
	}
}
