package app

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/novelty"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
)

// fakeStore is an in-memory baseline repository.
type fakeStore struct {
	mu     sync.Mutex
	saves  int
	fail   error
	digest string
}

func (f *fakeStore) Load(*baseline.Profile) error { return nil }
func (f *fakeStore) Save(p *baseline.Profile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.saves++
	f.digest = strings.Repeat("c", 63) + string(rune('0'+f.saves%10))
	return nil
}
func (f *fakeStore) Digest() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.digest == "" {
		return "none"
	}
	return f.digest
}

// outputApp is an App in mode m with an audit trail and (outside learn) a
// novelty sink in a temp dir, a fixed host name and no sensor.
func outputApp(t *testing.T, m mode.Mode) (*App, string, string) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Mode = m
	c.AuditPath = filepath.Join(dir, "audit.jsonl")
	c.Output.NoveltyPath = filepath.Join(dir, "novelty.jsonl")
	c.Output.TLP = "amber"
	a := New(c, "", &fakeStore{}, Meta{Version: "v-test"})
	a.selfPID = selfPID
	a.hostname = func() (string, error) { return "web01", nil }
	a.monoNow = nil
	aw, err := audit.Open(c.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	a.audit = aw
	t.Cleanup(func() { aw.Close() })
	if err := a.openNovelty(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.sink.Close() })
	return a, c.AuditPath, c.Output.NoveltyPath
}

func novelRows(t *testing.T, path string) []novelty.Row {
	t.Helper()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []novelty.Row
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		var r novelty.Row
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("novelty line %q: %v", l, err)
		}
		out = append(out, r)
	}
	return out
}

// learnEgress teaches the profile that curl egresses to 443.
func learnEgress(a *App) {
	ev := model.Event{Kind: kind.Connect, Comm: "curl", Net: model.NetConn{DestIP: "192.0.2.1", DestPort: 443}}
	for i := 0; i < 50; i++ {
		for k, v := range a.netExtract.Extract(ev) {
			a.profile.Observe(k, v)
		}
	}
}

func shell(pid int32) model.Event {
	return model.Event{Kind: kind.Connect, PID: pid, Comm: "sh", Time: time.Now(),
		Net: model.NetConn{DestIP: "203.0.113.9", DestPort: 4444}, Session: model.Session{LoginUID: -1}}
}

func TestAlertFindingWritesANoveltyRow(t *testing.T) {
	a, auditPath, novPath := outputApp(t, mode.Alert)
	learnEgress(a)
	a.handle(shell(4242))
	rows := novelRows(t, novPath)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want one finding", rows)
	}
	r := rows[0]
	if r.Status != novelty.StatusFinding || r.Source != "phage-host" || r.EntityKind != "host" || r.Entity != "web01" ||
		r.Profile != "connect" || r.Value != "203.0.113.9:4444" || r.TLP != "amber" || r.Score == nil || *r.Score < 0.4 {
		t.Errorf("row = %+v", r)
	}
	if recs := recordsOfKind(t, auditPath, audit.KindResponse); len(recs) != 1 || recs[0].Outcome != outcomeNotified {
		t.Errorf("the verdict is still audited and only notified: %+v", recs)
	}
	// A repeat in the same bucket is not written again.
	a.handle(shell(4243))
	if n := len(novelRows(t, novPath)); n != 1 {
		t.Errorf("rows after a repeat = %d, want 1", n)
	}
	if c := a.novelty.Counters(); c.Rows != 1 || c.Suppressed != 1 {
		t.Errorf("counters = %+v", c)
	}
}

func TestBelowNotifyWritesNothing(t *testing.T) {
	a, _, novPath := outputApp(t, mode.Alert)
	learnEgress(a)
	a.handle(model.Event{Kind: kind.Connect, PID: 1, Comm: "curl", Net: model.NetConn{DestIP: "192.0.2.1", DestPort: 443}})
	if rows := novelRows(t, novPath); len(rows) != 0 {
		t.Errorf("a normal event wrote %+v", rows)
	}
}

// Phage's scorer gives an unobserved feature class a neutral 0, which made
// the first egress of a host that never egressed while learning silent.
func TestUnlearnedClassIsReportedNotSilent(t *testing.T) {
	a, auditPath, novPath := outputApp(t, mode.Enforce)
	// Something was learned, but never an egress.
	for k, v := range a.execExtract.Extract(model.Event{Kind: kind.Exec, Comm: "cron", ParentComm: "systemd"}) {
		a.profile.Observe(k, v)
	}
	a.handle(shell(4242))
	rows := novelRows(t, novPath)
	if len(rows) != 1 || rows[0].Status != novelty.StatusUnlearned || rows[0].Score != nil || rows[0].Confidence != nil {
		t.Fatalf("rows = %+v, want one unscored unlearned row", rows)
	}
	if !strings.Contains(rows[0].Reasons[0], feature.FeatNetEgressComm) {
		t.Errorf("reasons = %q", rows[0].Reasons)
	}
	if recs := recordsOfKind(t, auditPath, audit.KindResponse); len(recs) != 0 {
		t.Errorf("unlearned is not a verdict: response records %+v", recs)
	}
	st := a.Status()
	if st.Unlearned != 1 || st.Alerts != 0 || st.Contained != 0 {
		t.Errorf("status = %+v", st)
	}
	a.handle(shell(4243))
	if n := len(novelRows(t, novPath)); n != 1 {
		t.Errorf("repeat wrote %d rows", n)
	}
}

func TestLearnModeWritesNoRowsAndLogsCapOnce(t *testing.T) {
	a, _, novPath := outputApp(t, mode.Learn)
	if a.novelty != nil || a.sink != nil {
		t.Fatal("learn mode must not open the novelty sink")
	}
	a.profile.SetMaxValuesPerKey(1)
	logs := captureLog(t)
	for port := uint16(1); port <= 5; port++ {
		a.handle(model.Event{Kind: kind.Connect, Comm: "curl", Net: model.NetConn{DestIP: "192.0.2.1", DestPort: port}})
	}
	if _, err := os.Stat(novPath); err == nil {
		t.Error("learn mode created the novelty file")
	}
	if n := strings.Count(logs.String(), "BASELINE CAP: feature "+feature.FeatNetEgressPort); n != 1 {
		t.Errorf("cap logged %d times for one key, want once:\n%s", n, logs.String())
	}
	if a.profile.Overflow() == 0 {
		t.Error("overflow not counted")
	}
}

func TestOpenNovelty(t *testing.T) {
	c := config.Default()
	c.Mode = mode.Alert
	c.Output.NoveltyPath = ""
	a := New(c, "", &fakeStore{}, Meta{})
	a.hostname = func() (string, error) { return "", errors.New("uts gone") }
	if err := a.openNovelty(); err == nil || !strings.Contains(err.Error(), "set output.entity") {
		t.Errorf("a host name that cannot be read must stop startup with advice, got %v", err)
	}
	a.hostname = func() (string, error) { return "has space", nil }
	if err := a.openNovelty(); err == nil {
		t.Error("a host name that is not a valid entity must stop startup")
	}
	c.Output.EntityKind, c.Output.Entity = "ip", "192.0.2.10"
	a = New(c, "", &fakeStore{}, Meta{})
	if err := a.openNovelty(); err != nil {
		t.Fatal(err)
	}
	if a.sink != nil || a.novelty == nil || a.ident.Entity != "192.0.2.10" || a.ident.EntityKind != "ip" {
		t.Errorf("no path: dedupe-only emitter and the configured entity; got sink=%v ident=%+v", a.sink, a.ident)
	}
	// An emitter without a sink must not panic on emit.
	a.reportUnlearned(shell(1), []string{"k"})

	c.Output.NoveltyPath = filepath.Join(t.TempDir(), "x", "n.jsonl")
	os.MkdirAll(c.Output.NoveltyPath, 0o700) // a directory where the file should be
	a = New(c, "", &fakeStore{}, Meta{})
	if err := a.openNovelty(); err == nil {
		t.Error("a sink that cannot be opened must stop startup")
	}
}

func TestStartupRecordNamesBaselineAndNovelty(t *testing.T) {
	a, auditPath, novPath := outputApp(t, mode.Alert)
	if err := a.announceStartup(nil, nil); err != nil {
		t.Fatal(err)
	}
	recs := recordsOfKind(t, auditPath, audit.KindStartup)
	if len(recs) != 1 {
		t.Fatal(recs)
	}
	r := recs[0]
	if r.BaselineSHA256 != "none" || r.NoveltyPath != novPath || r.NoveltyEntity != "host:web01" || r.TLP != "amber" {
		t.Errorf("startup = %+v", r)
	}
}

func TestHeartbeat(t *testing.T) {
	a, auditPath, _ := outputApp(t, mode.Alert)
	a.armed = []string{"freeze"}
	start := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	a.started = start
	readings := []uint64{5, 12, 3}
	i := 0
	a.drops = func() (uint64, error) { n := readings[i]; i++; return n, nil }
	a.monoNow = func() (uint64, bool) { return 10_000_000, true }

	for n := 0; n < 120; n++ {
		ev := model.Event{Kind: kind.Exec, Comm: "x", KernelNs: 10_000_000 - uint64(n%3)*1_000_000}
		a.handle(ev)
	}
	learnEgress(a)
	a.handle(shell(9)) // one finding row; the exec events above were one unlearned row

	e := a.heartbeat(start.Add(60 * time.Second))
	h := e.Health
	if e.Kind != audit.KindHeartbeat || e.Mode != "alert" || strings.Join(e.Features, ",") != "freeze" || e.BaselineSHA256 != "none" {
		t.Errorf("heartbeat = %+v", e)
	}
	if h.Events != 121 || h.EventsPerSec != 2.02 || h.Drops != 5 || h.DropsTotal != 5 || h.DropsError != "" {
		t.Errorf("health = %+v", *h)
	}
	if h.EnrichLagMsMax != 2 || h.EnrichLagMsAvg < 0.9 || h.EnrichLagMsAvg > 1.1 {
		t.Errorf("lag avg %.2f max %.2f, want ~1 and 2", h.EnrichLagMsAvg, h.EnrichLagMsMax)
	}
	if h.NoveltyRows != 2 || h.NoveltySuppressed != 119 {
		t.Errorf("novelty rows = %d suppressed = %d, want 2 and 119", h.NoveltyRows, h.NoveltySuppressed)
	}

	h2 := a.heartbeat(start.Add(120 * time.Second)).Health
	if h2.Drops != 7 || h2.DropsTotal != 12 || h2.Events != 0 || h2.NoveltyRows != 0 || h2.EnrichLagMsMax != 0 {
		t.Errorf("second interval = %+v", *h2)
	}
	// A counter that went backwards (sensor reloaded) reports the new total.
	if h3 := a.heartbeat(start.Add(180 * time.Second)).Health; h3.Drops != 3 {
		t.Errorf("after a reset: drops = %d, want 3", h3.Drops)
	}
	a.drops = func() (uint64, error) { return 0, errors.New("no phage_drops map") }
	if h4 := a.heartbeat(start.Add(240 * time.Second)).Health; h4.DropsError != "no phage_drops map" || h4.Drops != 0 {
		t.Errorf("unreadable counter = %+v", *h4)
	}
	recs := recordsOfKind(t, auditPath, audit.KindHeartbeat)
	if len(recs) != 4 || recs[0].Health == nil {
		t.Fatalf("heartbeat records = %d", len(recs))
	}
	// Zero values are present in the JSON, so a SIEM rule can match them.
	raw, _ := os.ReadFile(auditPath)
	for _, f := range []string{`"drops":0`, `"novelty_errors":0`, `"drops_error":""`} {
		if !strings.Contains(string(raw), f) {
			t.Errorf("audit trail lacks %s", f)
		}
	}
	st := a.Status()
	if st.LastHeartbeat != "2026-11-04T10:04:00Z" || st.DropsError == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestHeartbeatWithoutSensorOrSink(t *testing.T) {
	a, _, _ := outputApp(t, mode.Learn)
	a.started = time.Now().Add(-time.Minute)
	if h := a.heartbeat(time.Now()).Health; h.DropsError != "sensor not loaded" {
		t.Errorf("health = %+v", *h)
	}
}

func TestLagBackdatesEventTime(t *testing.T) {
	a, _, _ := outputApp(t, mode.Learn)
	a.monoNow = func() (uint64, bool) { return uint64(5 * time.Second), true }
	ev := model.Event{KernelNs: uint64(3 * time.Second)}
	before := time.Now()
	a.noteLag(&ev)
	if d := before.Sub(ev.Time); d < 1900*time.Millisecond || d > 2100*time.Millisecond {
		t.Errorf("event time back-dated by %v, want ~2s", d)
	}
	future := model.Event{KernelNs: uint64(9 * time.Second)} // clock disagreement: leave the time alone
	a.noteLag(&future)
	if !future.Time.IsZero() || a.lag.n != 1 {
		t.Errorf("a kernel time in the future must be ignored (n=%d)", a.lag.n)
	}
}

func TestCheckpointSavesOnlyChanges(t *testing.T) {
	a, _, _ := outputApp(t, mode.Learn)
	st := a.store.(*fakeStore)
	a.savedGen = a.profile.Generation()
	a.checkpoint()
	if st.saves != 0 {
		t.Fatal("an unchanged baseline must not be rewritten")
	}
	a.profile.Observe("k", 1)
	a.checkpoint()
	a.checkpoint()
	if st.saves != 1 {
		t.Fatalf("saves = %d, want 1", st.saves)
	}
	a.profile.Observe("k", 2)
	st.fail = errors.New("disk full")
	logs := captureLog(t)
	a.checkpoint()
	if a.ckptErrors != 1 || !strings.Contains(logs.String(), "BASELINE CHECKPOINT FAILED") {
		t.Errorf("a failed checkpoint must be counted and loud (errors=%d)", a.ckptErrors)
	}
	st.fail = nil
	a.checkpoint() // retried at the next interval
	if st.saves != 2 {
		t.Errorf("saves = %d, want the retry", st.saves)
	}
	if err := a.onShutdown(); err != nil || st.saves != 3 {
		t.Errorf("shutdown save: %v (saves %d)", err, st.saves)
	}
}

// A checkpoint runs while the event loop keeps learning (go test -race).
func TestCheckpointConcurrentWithLearning(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.StatePath = filepath.Join(dir, "baseline.json")
	a, _, _ := outputApp(t, mode.Learn)
	a.cfg.StatePath = c.StatePath
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			a.handle(model.Event{Kind: kind.Exec, Comm: "x", ParentComm: "y", PID: int32(i)})
		}
	}()
	for i := 0; i < 20; i++ {
		a.checkpoint()
	}
	wg.Wait()
}

// syncBuffer is a log sink safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog sends the standard logger to a buffer for the rest of the test.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })
	return buf
}

// deploy/wazuh's startup rules read the status from the end of the reason
// (status is a Wazuh static field name), so the format is a contract.
func TestStartupReasonEndsWithStatus(t *testing.T) {
	for status, armed := range map[string][]string{audit.StatusNone: nil, audit.StatusArmed: {config.FeatureFreeze}} {
		c := config.Default()
		c.Mode = mode.Enforce
		a, path := appWithAudit(t, c, Meta{})
		if err := a.announceStartup(armed, nil); err != nil {
			t.Fatal(err)
		}
		recs := recordsOfKind(t, path, audit.KindStartup)
		if len(recs) != 1 || !strings.HasSuffix(recs[0].Reason, " status="+status) {
			t.Errorf("startup reason %q must end with status=%s", recs[0].Reason, status)
		}
	}
}
