package novelty

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
)

var (
	testID  = Identity{Source: "phage-host", EntityKind: "host", Entity: "web01", TLP: "amber", Bucket: time.Hour}
	evTime  = time.Date(2026, 3, 28, 13, 5, 7, 123456789, time.UTC)
	emitAt  = evTime.Add(40 * time.Millisecond)
	testSHA = strings.Repeat("ab", 32)
)

func events() map[string]model.Event {
	return map[string]model.Event{
		"exec":         {Time: evTime, Kind: kind.Exec, PID: 10, Comm: "sh", ParentComm: "php-fpm", Exe: "/usr/bin/dash"},
		"connect-v4":   {Time: evTime, Kind: kind.Connect, PID: 11, Comm: "sh", Net: model.NetConn{DestIP: "192.0.2.7", DestPort: 4444, Family: 2}},
		"connect-v6":   {Time: evTime, Kind: kind.Connect, PID: 12, Comm: "sh", Net: model.NetConn{DestIP: "2001:db8::7", DestPort: 443, Family: 10}},
		"file-write":   {Time: evTime, Kind: kind.FileWrite, PID: 13, Comm: "bash", File: model.FileWrite{Path: "/root/.ssh/authorized_keys", Category: "ssh_authorized_keys"}},
		"enable":       {Time: evTime, Kind: kind.Enable, PID: 14, Comm: "x", EnableOp: "userns"},
		"creds":        {Time: evTime, Kind: kind.CredsChange, PID: 15, Comm: "rootshell", Exe: "/tmp/rootshell"},
		"self-defense": {Time: evTime, Kind: kind.SelfDefense, PID: 16, Comm: "kill", SelfDefOp: "SIGKILL"},
		"honeytoken":   {Time: evTime, Kind: kind.Honeytoken, PID: 17, Comm: "cat", File: model.FileWrite{Path: "/root/.aws/credentials"}},
		"no-exe":       {Time: evTime, Kind: kind.Exec, PID: 18, Comm: "gone"},
		"unknown":      {Time: evTime, Kind: kind.Unknown, PID: 19, Comm: "x"},
	}
}

func learned() verdict.Verdict {
	return verdict.Verdict{Score: 0.8333333, Reasons: []verdict.Reason{
		{Feature: "exec.child_id", Contribution: 0.3, Detail: "minor", Surprise: 1, Confidence: 1, Support: 0, Samples: 400},
		{Feature: "exec.parent_child_id", Contribution: 0.7, Detail: "never-seen pair", Surprise: 0.8, Confidence: 0.6, Support: 1, Samples: 9},
	}}
}

func TestEveryRowShapeSatisfiesTheSchema(t *testing.T) {
	intrinsic := verdict.Verdict{Score: 1, Reasons: []verdict.Reason{{Feature: "self.tamper", Contribution: 1, Detail: "tamper", Confidence: 1}}}
	for name, ev := range events() {
		for _, r := range []Row{
			testID.Finding(ev, learned(), testSHA, emitAt),
			testID.Finding(ev, intrinsic, testSHA, emitAt),
			testID.Finding(ev, verdict.Verdict{Score: 0.5}, testSHA, emitAt),
			testID.Unlearned(ev, []string{"b", "a"}, testSHA, emitAt),
		} {
			t.Run(name+"/"+r.Status, func(t *testing.T) { validateRow(t, r) })
		}
	}
	for _, l := range []string{"clear", "green", "amber", "amber+strict", "red"} {
		id := testID
		id.TLP = l
		validateRow(t, id.Finding(events()["exec"], learned(), testSHA, emitAt))
	}
	id := testID
	id.EntityKind, id.Entity = "ip", "192.0.2.10"
	validateRow(t, id.Unlearned(events()["connect-v4"], []string{"k"}, testSHA, emitAt))
}

func TestFindingRow(t *testing.T) {
	r := testID.Finding(events()["exec"], learned(), testSHA, emitAt)
	if r.Status != StatusFinding || r.Source != "phage-host" || r.SourceKind != "heuristic" || r.Profile != "exec" ||
		r.EntityKind != "host" || r.Entity != "web01" || r.Value != "/usr/bin/dash" || r.TLP != "amber" || r.Count != 1 {
		t.Fatalf("row = %+v", r)
	}
	if *r.Score != 0.8333 || *r.Confidence != 0.6 || *r.Support != 1 || *r.EntityTotal != 9 {
		t.Errorf("score/confidence/support/total = %v/%v/%v/%v; want the top reason's terms",
			*r.Score, *r.Confidence, *r.Support, *r.EntityTotal)
	}
	if r.Time != "2026-03-28T13:05:07.123456Z" || r.AsOf != "2026-03-28T13:05:07.163456Z" {
		t.Errorf("time=%s as_of=%s: want the event time and the emit time, UTC microseconds", r.Time, r.AsOf)
	}
	if !strings.HasPrefix(r.Reasons[0], "exec.parent_child_id: never-seen pair") || r.Reasons[len(r.Reasons)-1] != "baseline sha256:"+testSHA {
		t.Errorf("reasons = %q; want the top reason first and the baseline last", r.Reasons)
	}
	if !strings.Contains(r.Message, "web01: exec /usr/bin/dash by sh (pid 10): never-seen pair") {
		t.Errorf("message = %q", r.Message)
	}
}

func TestUnlearnedRowHasNoScore(t *testing.T) {
	r := testID.Unlearned(events()["connect-v4"], []string{"net.b", "net.a"}, testSHA, emitAt)
	if r.Status != StatusUnlearned || r.Score != nil || r.Confidence != nil {
		t.Fatalf("unlearned row must carry no score/confidence: %+v", r)
	}
	if *r.EntityTotal != 0 || r.Value != "192.0.2.7:4444" || r.Profile != "connect" {
		t.Errorf("row = %+v", r)
	}
	if !strings.HasSuffix(r.Message, "(unlearned)") {
		t.Errorf("message %q: deploy/wazuh rule 100832 matches the (unlearned) suffix", r.Message)
	}
	if r.Reasons[0] != "no observations in the baseline for net.a, net.b" {
		t.Errorf("reasons = %q", r.Reasons)
	}
}

func TestValuesAndProfiles(t *testing.T) {
	want := map[string][2]string{
		"exec":         {"exec", "/usr/bin/dash"},
		"connect-v4":   {"connect", "192.0.2.7:4444"},
		"connect-v6":   {"connect", "[2001:db8::7]:443"},
		"file-write":   {"file-write", "/root/.ssh/authorized_keys"},
		"enable":       {"enable", "userns"},
		"creds":        {"creds-change", "/tmp/rootshell"},
		"self-defense": {"self-defense", "SIGKILL"},
		"honeytoken":   {"honeytoken", "/root/.aws/credentials"},
		"no-exe":       {"exec", "gone"},
	}
	evs := events()
	for name, w := range want {
		if p, v := Profile(evs[name].Kind), Value(evs[name]); p != w[0] || v != w[1] {
			t.Errorf("%s: profile=%q value=%q, want %q %q", name, p, v, w[0], w[1])
		}
	}
}

func TestUIDIsDeterministicAndBucketed(t *testing.T) {
	ev := events()["file-write"]
	a := testID.Finding(ev, learned(), testSHA, emitAt)
	b := testID.Finding(ev, verdict.Verdict{Score: 0.9}, "other", emitAt.Add(time.Minute))
	if a.UID != b.UID {
		t.Error("the same finding in the same bucket must have the same uid (score, baseline and as_of are not in it)")
	}
	if len(a.UID) > 128 || !strings.HasPrefix(a.UID, "phage-") {
		t.Errorf("uid %q", a.UID)
	}
	later := ev
	later.Time = ev.Time.Add(time.Hour)
	if testID.Finding(later, learned(), testSHA, emitAt).UID == a.UID {
		t.Error("the next bucket must give a new uid")
	}
	other := ev
	other.File.Path = "/root/.ssh/authorized_keys2"
	if testID.Finding(other, learned(), testSHA, emitAt).UID == a.UID {
		t.Error("a different value must give a new uid")
	}
	if testID.Unlearned(ev, nil, testSHA, emitAt).UID == a.UID {
		t.Error("a different status must give a new uid")
	}
	id := testID
	id.EntityKind = "ip"
	if id.Finding(ev, learned(), testSHA, emitAt).UID == a.UID {
		t.Error("a different entity kind must give a new uid")
	}
}

func TestLongAndHostileTextIsClipped(t *testing.T) {
	ev := events()["file-write"]
	ev.File.Path = "/var/www/" + strings.Repeat("é", 3000) + "\n\x1b[31m.php"
	ev.Comm = "x\ny"
	v := verdict.Verdict{Score: 0.7, Reasons: []verdict.Reason{{Feature: "f", Contribution: 0.7, Detail: strings.Repeat("d", 1000), Confidence: 1}}}
	id := testID
	id.Entity = strings.Repeat("h", 600)
	r := id.Finding(ev, v, testSHA, emitAt)
	validateRow(t, r)
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "\n") {
		t.Error("a row must stay on one line")
	}
}

func TestSinkFileModeAndRefusals(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "novelty.jsonl")
	s, err := OpenSink(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("sink created %v, want 0600", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm() != 0o700 {
		t.Errorf("sink directory created %v, want 0700", fi.Mode().Perm())
	}
	target := filepath.Join(dir, "target")
	os.WriteFile(target, nil, 0o600)
	link := filepath.Join(dir, "link.jsonl")
	os.Symlink(target, link)
	if _, err := OpenSink(link, 0); err == nil {
		t.Error("a symlinked sink must be refused")
	}
	fifo := filepath.Join(dir, "fifo.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err == nil {
		if _, err := OpenSink(fifo, 0); err == nil {
			t.Error("a FIFO sink must be refused")
		}
	}
}

func readRows(t *testing.T, p string) []Row {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []Row
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		var r Row
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		out = append(out, r)
	}
	return out
}

func TestSinkAppendsAndRotates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "novelty.jsonl")
	r := testID.Finding(events()["exec"], learned(), testSHA, emitAt)
	b, _ := json.Marshal(r)
	line := int64(len(b) + 1)
	s, err := OpenSink(p, 3*line) // three rows fit; the fourth rotates
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 4; i++ {
		if err := s.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(readRows(t, p+".1")); n != 3 {
		t.Errorf("rotated file has %d rows, want 3", n)
	}
	if n := len(readRows(t, p)); n != 1 {
		t.Errorf("new file has %d rows, want 1", n)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("rotated-in file is %v, want 0600", fi.Mode().Perm())
	}

	// An external copytruncate resets the size: no needless rotation follows.
	os.Truncate(p, 0)
	os.Remove(p + ".1")
	for i := 0; i < 3; i++ {
		s.Write(r)
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Error("rotated although the file was truncated externally")
	}
	if n := len(readRows(t, p)); n != 3 {
		t.Errorf("after copytruncate: %d rows, want 3", n)
	}
}

type failingWriter struct {
	fail bool
	rows []Row
}

func (f *failingWriter) Write(r Row) error {
	if f.fail {
		return errors.New("disk full")
	}
	f.rows = append(f.rows, r)
	return nil
}

func TestEmitterDedupesAndCounts(t *testing.T) {
	w := &failingWriter{}
	var logged []string
	e := NewEmitter(w, testID, 0, func(f string, a ...any) { logged = append(logged, f) })
	now := evTime
	e.now = func() time.Time { return now }
	r := testID.Finding(events()["exec"], learned(), testSHA, emitAt)
	if !e.Emit(r) || e.Emit(r) {
		t.Fatal("the first emit writes, a repeat within the bucket does not")
	}
	other := testID.Finding(events()["enable"], learned(), testSHA, emitAt)
	e.Emit(other)
	if c := e.Counters(); c.Rows != 2 || c.Suppressed != 1 || c.Errors != 0 {
		t.Errorf("counters = %+v", c)
	}
	now = now.Add(3 * time.Hour)
	if !e.Emit(r) {
		t.Error("a uid is forgotten after its window")
	}

	w.fail = true
	fresh := testID.Finding(events()["honeytoken"], learned(), testSHA, emitAt)
	e.Emit(fresh)
	e.Emit(fresh) // not deduped: the failed row was never written
	if c := e.Counters(); c.Errors != 2 {
		t.Errorf("errors = %d, want 2", c.Errors)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "NOVELTY SINK WRITE FAILED") {
		t.Errorf("want one loud line for a burst of failures, got %q", logged)
	}
	now = now.Add(2 * time.Minute)
	e.Emit(fresh)
	if len(logged) != 2 {
		t.Errorf("a failure after the quiet period must be logged again (%d lines)", len(logged))
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	var e *Emitter
	if e.Emit(Row{}) || e.Counters() != (Counters{}) {
		t.Error("a nil emitter is a disabled sink")
	}
}

func TestSinkWriteErrorIsReturned(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	s := &Sink{path: "/dev/full"}
	f, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip(err)
	}
	s.f = f
	defer s.Close()
	if err := s.Write(testID.Finding(events()["exec"], learned(), testSHA, emitAt)); err == nil {
		t.Error("a failed write must be reported")
	}
}

func TestEmitterWithoutSinkOnlyDedupes(t *testing.T) {
	e := NewEmitter(nil, testID, 0, t.Logf)
	r := testID.Finding(events()["exec"], learned(), testSHA, emitAt)
	if !e.Emit(r) || e.Emit(r) {
		t.Fatal("dedupe must work without a sink")
	}
	if c := e.Counters(); c.Rows != 0 || c.Suppressed != 1 {
		t.Errorf("counters = %+v: nothing was written", c)
	}
}

func TestBurstRowSatisfiesTheSchema(t *testing.T) {
	r := testID.Finding(events()["connect-v4"], learned(), testSHA, emitAt)
	b := testID.Burst(r, 21, emitAt)
	validateRow(t, b)
	if b.Status != StatusBurst || b.Value != "" || b.Score != nil || b.Count != 21 || b.UID == r.UID ||
		!strings.HasSuffix(b.Message, "(burst)") {
		t.Errorf("burst = %+v", b)
	}
	other := events()["connect-v4"]
	other.Net.DestPort = 9
	if testID.Burst(testID.Finding(other, learned(), testSHA, emitAt), 21, emitAt).UID != b.UID {
		t.Error("one burst uid per profile, entity and bucket, whatever value tripped it")
	}
}

// A flood of distinct values (a scan, or a host whose baseline lacks a whole
// class) is bounded per profile and bucket: N rows, then one burst row.
func TestEmitterCapsNewRowsPerProfileAndBucket(t *testing.T) {
	w := &failingWriter{}
	e := NewEmitter(w, testID, 3, t.Logf)
	now := evTime
	e.now = func() time.Time { return now }
	ev := events()["connect-v4"]
	for port := 1; port <= 50; port++ {
		ev.Net.DestPort = uint16(port)
		e.Emit(testID.Unlearned(ev, []string{"k"}, testSHA, emitAt))
	}
	e.Emit(testID.Finding(events()["exec"], learned(), testSHA, emitAt)) // another profile is not capped
	if len(w.rows) != 5 || w.rows[3].Status != StatusBurst || w.rows[3].Count != 4 || w.rows[4].Profile != "exec" {
		t.Fatalf("rows = %d (want 3 + burst + exec): %+v", len(w.rows), w.rows)
	}
	if c := e.Counters(); c.OverCap != 47 || c.Bursts != 1 || c.Rows != 5 {
		t.Errorf("counters = %+v", c)
	}
	// The next bucket starts a new count.
	later := ev
	later.Time = ev.Time.Add(time.Hour)
	now = now.Add(time.Hour)
	if !e.Emit(testID.Unlearned(later, []string{"k"}, testSHA, emitAt)) {
		t.Error("a new bucket must not inherit the cap")
	}
}

// Once the dedupe set is full of live entries, an emit must not scan it:
// the scan is throttled to once a minute.
func TestFullDedupeSetIsNotScannedPerEmit(t *testing.T) {
	e := NewEmitter(nil, testID, 0, t.Logf)
	now := evTime
	e.now = func() time.Time { return now }
	for i := 0; i < maxSeen; i++ {
		e.seen[strconv.Itoa(i)] = now
	}
	e.lastSweep = now
	ev := events()["file-write"]
	start := time.Now()
	for i := 0; i < 2000; i++ {
		ev.File.Path = "/root/.ssh/k" + strconv.Itoa(i)
		e.Emit(testID.Finding(ev, learned(), testSHA, emitAt))
	}
	if e.sweeps != 0 {
		t.Errorf("swept %d times within a minute", e.sweeps)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("2000 emits against a full set took %v", d)
	}
	now = now.Add(time.Minute)
	e.Emit(testID.Finding(events()["exec"], learned(), testSHA, emitAt))
	if e.sweeps != 1 {
		t.Errorf("sweeps after a minute = %d, want 1", e.sweeps)
	}
	if len(e.seen) > maxSeen {
		t.Errorf("dedupe set grew past its bound: %d", len(e.seen))
	}
}

func TestSinkRefusesRedAndNonCanonicalLabels(t *testing.T) {
	s, err := OpenSink(filepath.Join(t.TempDir(), "n.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, l := range []string{"red", "TLP:AMBER", "Amber", "white", ""} {
		id := testID
		id.TLP = l
		if err := s.Write(id.Finding(events()["exec"], learned(), testSHA, emitAt)); err == nil {
			t.Errorf("sink wrote a row labelled %q", l)
		}
	}
}

// N1: noise must not hide a finding. Unlearned rows exhaust their own budget;
// a finding has a separate one, and one at or above the contain threshold is
// never capped at all.
func TestFindingsAreNotHiddenByUnlearnedNoise(t *testing.T) {
	w := &failingWriter{}
	var logged []string
	e := NewEmitter(w, testID, 20, func(f string, a ...any) { logged = append(logged, f) })
	e.ExemptFindingsAt(0.8)
	now := evTime.Truncate(time.Hour)
	e.now = func() time.Time { return now }
	ev := events()["connect-v4"]
	ev.Time = now
	for port := 1; port <= 21; port++ {
		ev.Net.DestPort = uint16(port)
		e.Emit(testID.Unlearned(ev, []string{"k"}, testSHA, now))
	}
	if len(w.rows) != 21 || w.rows[20].Status != StatusBurst {
		t.Fatalf("want 20 unlearned + 1 burst, got %d", len(w.rows))
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "NOVELTY BURST") {
		t.Errorf("want one NOVELTY BURST line, got %q", logged)
	}
	now = now.Add(30 * time.Minute)
	ev.Time, ev.Net.DestPort = now, 4444
	high := verdict.Verdict{Score: 0.99, Reasons: []verdict.Reason{{Feature: "net.egress_comm_id", Contribution: 0.99, Detail: "c2", Confidence: 1, Samples: 99}}}
	if !e.Emit(testID.Finding(ev, high, testSHA, now)) {
		t.Fatal("a 0.99 finding after unlearned noise in the same bucket must be written")
	}
	if last := w.rows[len(w.rows)-1]; last.Status != StatusFinding || *last.Score != 0.99 {
		t.Errorf("last row = %+v", last)
	}

	// Findings below contain have their own budget of 20, then a burst
	// distinct from the unlearned burst; findings at/above contain pass.
	for port := 5000; port < 5025; port++ {
		ev.Net.DestPort = uint16(port)
		e.Emit(testID.Finding(ev, learned(), testSHA, now)) // score 0.83 >= 0.8: exempt
	}
	mid := verdict.Verdict{Score: 0.5, Reasons: []verdict.Reason{{Feature: "f", Contribution: 0.5, Detail: "d", Confidence: 1}}}
	var bursts []Row
	for port := 6000; port < 6025; port++ {
		ev.Net.DestPort = uint16(port)
		e.Emit(testID.Finding(ev, mid, testSHA, now))
	}
	for _, r := range w.rows {
		if r.Status == StatusBurst {
			bursts = append(bursts, r)
		}
	}
	if len(bursts) != 2 || bursts[0].UID == bursts[1].UID {
		t.Fatalf("want separate unlearned and finding bursts with distinct uids, got %d", len(bursts))
	}
	if n := len(w.rows); n != 21+1+25+21 {
		t.Errorf("rows = %d, want 21 unlearned/burst + 1 + 25 exempt + 20 findings + burst", n)
	}
	if !strings.Contains(bursts[1].Message, "finding") || bursts[1].Count != 21 {
		t.Errorf("finding burst = %+v", bursts[1])
	}
}

func TestSweepDropsFinishedBuckets(t *testing.T) {
	e := NewEmitter(nil, testID, 2, t.Logf)
	now := evTime
	e.now = func() time.Time { return now }
	ev := events()["exec"]
	e.Emit(testID.Unlearned(ev, nil, testSHA, now))
	if len(e.perBucket) != 1 || len(e.seen) != 1 {
		t.Fatalf("perBucket=%d seen=%d", len(e.perBucket), len(e.seen))
	}
	now = now.Add(3 * time.Hour) // past two windows; a sweep is due
	later := ev
	later.Time = now
	e.Emit(testID.Unlearned(later, nil, testSHA, now))
	if len(e.perBucket) != 1 || len(e.seen) != 1 {
		t.Errorf("finished buckets and expired uids must be swept: perBucket=%d seen=%d", len(e.perBucket), len(e.seen))
	}
}
