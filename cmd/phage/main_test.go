package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/control"
)

func writeBaseline(t *testing.T, obs map[string][]float64) (string, string) {
	t.Helper()
	p := baseline.NewProfile()
	for k, vs := range obs {
		for _, v := range vs {
			p.Observe(k, v)
		}
	}
	b, _ := json.Marshal(p.Export())
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, b, 0o400); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return path, hex.EncodeToString(sum[:])
}

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := cmdBaseline(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestBaselineShowAndDiff(t *testing.T) {
	oldP, oldSum := writeBaseline(t, map[string][]float64{"net.egress_port": {443, 443, 443, 443, 443}})
	newP, newSum := writeBaseline(t, map[string][]float64{"net.egress_port": {443, 443, 443, 443, 443, 4444}})
	before, _ := os.ReadFile(oldP)

	code, out, _ := run("show", oldP)
	if code != 0 || !strings.Contains(out, "sha256="+oldSum) || !strings.Contains(out, "net.egress_port") {
		t.Fatalf("show = %d\n%s", code, out)
	}
	code, out, _ = run("diff", oldP, newP)
	if code != 0 || !strings.Contains(out, "sha256="+newSum) || !strings.Contains(out, "added (1): [4444]") {
		t.Fatalf("diff = %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(oldP); !bytes.Equal(before, after) {
		t.Error("baseline commands must not modify files")
	}
}

func TestBaselineRefusals(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{trunc"), 0o600)
	for _, args := range [][]string{{}, {"show"}, {"diff", bad}, {"frob", bad}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want usage (2)", args, code)
		}
	}
	if code, _, msg := run("show", bad); code != 1 || !strings.Contains(msg, "not a valid baseline") {
		t.Errorf("corrupt file: exit %d %q", code, msg)
	}
	if code, _, _ := run("show", filepath.Join(t.TempDir(), "missing")); code != 1 {
		t.Errorf("missing file: exit %d", code)
	}
}

func TestFormatHealth(t *testing.T) {
	three := uint64(3)
	out := formatHealth(control.Status{Drops: &three, BaselineState: "warming", EventsPerSec: 12.5, LastHeartbeat: "2026-11-04T10:00:00Z",
		BaselineSHA256: "abc", NoveltyPath: "/var/lib/phage/novelty.jsonl", NoveltyRows: 2})
	for _, want := range []string{"drops=3", "baseline_state=warming", "events_per_sec=12.50", "baseline_sha256=abc", "novelty=/var/lib/phage/novelty.jsonl rows=2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	out = formatHealth(control.Status{DropsError: "no map\nFORGED"})
	if !strings.Contains(out, "drops=unknown") || strings.Contains(out, "\nFORGED") || !strings.Contains(out, "last_heartbeat=none yet") {
		t.Errorf("error rendering: %q", out)
	}
}

func TestBaselineRefusesFIFOAndCleansOutput(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan int, 1)
	go func() { code, _, _ := run("show", fifo); done <- code }()
	select {
	case code := <-done:
		if code != 1 {
			t.Errorf("FIFO: exit %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("show blocked on a FIFO")
	}
	// A key or value carrying control bytes is printed escaped.
	p := filepath.Join(dir, "evil.json")
	os.WriteFile(p, []byte(`{"counts":{"k\u001b[31m\nFORGED":{"1\n2":1}},"totals":{"k\u001b[31m\nFORGED":1}}`), 0o600)
	q := filepath.Join(dir, "empty.json")
	os.WriteFile(q, []byte(`{"counts":{},"totals":{}}`), 0o600)
	for _, args := range [][]string{{"show", p}, {"diff", q, p}} {
		_, out, _ := run(args...)
		if strings.Contains(out, "\x1b") || strings.Contains(out, "\nFORGED") || !strings.Contains(out, `\nFORGED`) {
			t.Errorf("%v: output not escaped:\n%s", args, out)
		}
	}
}
