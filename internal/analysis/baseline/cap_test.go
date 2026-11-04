package baseline

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMaxValuesPerKeyCountsOverflow(t *testing.T) {
	p := NewProfile()
	p.SetMaxValuesPerKey(3)
	for v := 1; v <= 3; v++ {
		if p.Observe("net.egress_port", float64(v)) {
			t.Fatalf("value %d refused below the cap", v)
		}
	}
	if !p.Observe("net.egress_port", 4) || !p.Observe("net.egress_port", 5) {
		t.Fatal("new values past the cap must be refused")
	}
	if p.Observe("net.egress_port", 2) {
		t.Fatal("a value already learned is still counted at the cap")
	}
	if p.Overflow() != 2 || p.Samples("net.egress_port") != 6 {
		t.Errorf("overflow=%d samples=%d, want 2 and 6 (refused values still count as observations)", p.Overflow(), p.Samples("net.egress_port"))
	}
	if p.Count("net.egress_port", 4) != 0 || p.Surprise("net.egress_port", 4) != 1 {
		t.Error("a refused value stays novel")
	}
	if p.Count("net.egress_port", 2) != 2 {
		t.Errorf("count(2) = %d, want 2", p.Count("net.egress_port", 2))
	}

	// The overflow survives a save/load, and a lower cap keeps what was learned.
	q := NewProfile()
	q.Import(p.Export())
	q.SetMaxValuesPerKey(1)
	if q.Overflow() != 2 || q.Count("net.egress_port", 3) != 1 {
		t.Errorf("after import: overflow=%d count(3)=%d", q.Overflow(), q.Count("net.egress_port", 3))
	}
	if !q.Observe("net.egress_port", 9) {
		t.Error("a lowered cap refuses new values")
	}
}

func TestNoCapByDefault(t *testing.T) {
	p := NewProfile()
	for v := 0; v < 20000; v++ {
		if p.Observe("k", float64(v)) {
			t.Fatal("NewProfile has no cap until one is set")
		}
	}
}

func TestGenerationTracksChanges(t *testing.T) {
	p := NewProfile()
	g := p.Generation()
	p.Observe("k", 1)
	if p.Generation() == g {
		t.Error("Observe must change the generation")
	}
	g = p.Generation()
	p.Surprise("k", 1)
	p.Export()
	if p.Generation() != g {
		t.Error("reads must not change the generation")
	}
}

func snap(t *testing.T, obs map[string][]float64) Snapshot {
	t.Helper()
	p := NewProfile()
	for k, vs := range obs {
		for _, v := range vs {
			p.Observe(k, v)
		}
	}
	return p.Export()
}

func TestDiff(t *testing.T) {
	oldS := snap(t, map[string][]float64{
		"net.egress_port": {443, 443, 443, 443, 22, 22, 22, 22, 22},
		"gone":            {1},
		"same":            {7},
	})
	newS := snap(t, map[string][]float64{
		"net.egress_port": {443, 443, 443, 443, 443, 22, 4444},
		"fresh":           {1},
		"same":            {7},
	})
	diffs := Diff(oldS, newS)
	keys := []string{}
	for _, d := range diffs {
		keys = append(keys, d.Key)
	}
	if strings.Join(keys, ",") != "fresh,gone,net.egress_port" {
		t.Fatalf("changed keys = %v (unchanged keys are left out, sorted)", keys)
	}
	d := diffs[2]
	if strings.Join(d.Added, ",") != "4444" || len(d.Removed) != 0 ||
		strings.Join(d.NewlyEstablished, ",") != "443" || strings.Join(d.NoLongerEstablished, ",") != "22" {
		t.Errorf("port diff = %+v", d)
	}
	if d.Old.Total != 9 || d.New.Total != 7 || d.Old.Established != 1 || d.New.Established != 1 {
		t.Errorf("summaries = %+v / %+v", d.Old, d.New)
	}
	var buf bytes.Buffer
	WriteDiff(&buf, diffs, 0)
	for _, want := range []string{"net.egress_port", "added (1): [4444]", "newly established (will no longer alert) (1): [443]", "no longer established (will alert again) (1): [22]"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("diff output lacks %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	WriteDiff(&buf, Diff(oldS, oldS), 0)
	if strings.TrimSpace(buf.String()) != "no differences" {
		t.Errorf("self-diff = %q", buf.String())
	}
}

func TestDiffTruncatesLongLists(t *testing.T) {
	var vs []float64
	for i := 0; i < 50; i++ {
		vs = append(vs, float64(i))
	}
	var buf bytes.Buffer
	WriteDiff(&buf, Diff(Snapshot{}, snap(t, map[string][]float64{"k": vs})), 5)
	if !strings.Contains(buf.String(), "added (50): [0 1 2 3 4] ... and 45 more") {
		t.Errorf("output:\n%s", buf.String())
	}
}

func TestSummaryAndParse(t *testing.T) {
	p := NewProfile()
	p.SetMaxValuesPerKey(1)
	for i := 0; i < 5; i++ {
		p.Observe("a", 1)
	}
	p.Observe("a", 2)
	b, _ := json.Marshal(p.Export())
	s, err := ParseSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	got := Summarize(s)
	if len(got) != 1 || got[0] != (KeySummary{Key: "a", Total: 6, Distinct: 1, Established: 1, Overflow: 1}) {
		t.Errorf("summary = %+v", got)
	}
	var buf bytes.Buffer
	WriteSummary(&buf, s)
	if !strings.Contains(buf.String(), "overflow") || !strings.Contains(buf.String(), "a ") {
		t.Errorf("summary output:\n%s", buf.String())
	}
	if _, err := ParseSnapshot([]byte("{trunc")); err == nil {
		t.Error("a corrupt baseline must not parse")
	}
}
