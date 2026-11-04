package behavioral

import (
	"strings"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
)

// trainNormal teaches the profile what this host's normal looks like: root is
// only ever reached inside an interactive login, never by an unprivileged
// process with no session.
func trainNormal(p *baseline.Profile, n int) {
	normal := feature.Vector{
		feature.FeatGainedRoot:        1,
		feature.FeatRaisedToRoot:      0,
		feature.FeatRaiseNoSession:    0,
		feature.FeatInteractiveOrigin: 1,
		feature.FeatHasTTY:            1,
		feature.FeatLineageDepth:      2,
		feature.FeatParentComm:        111,
	}
	for i := 0; i < n; i++ {
		for k, v := range normal {
			p.Observe(k, v)
		}
	}
}

func TestAttackScoresHighWithReason(t *testing.T) {
	p := baseline.NewProfile()
	trainNormal(p, 100)
	a := New(p)

	attack := feature.Vector{
		feature.FeatGainedRoot:        1,
		feature.FeatRaisedToRoot:      1,
		feature.FeatRaiseNoSession:    1, // never seen in training
		feature.FeatInteractiveOrigin: 0, // never seen in training
		feature.FeatHasTTY:            0,
		feature.FeatLineageDepth:      4,
		feature.FeatParentComm:        999, // unknown parent
	}
	v := a.Score(attack)
	if v.Score < 0.7 {
		t.Fatalf("attack score = %.2f, want >= 0.7", v.Score)
	}
	joined := ""
	for _, r := range v.Reasons {
		joined += r.Detail + " | "
	}
	if !strings.Contains(joined, "no login session") {
		t.Errorf("expected a 'no login session' reason, got: %s", joined)
	}
}

func TestNormalScoresLow(t *testing.T) {
	p := baseline.NewProfile()
	trainNormal(p, 100)
	a := New(p)

	normal := feature.Vector{
		feature.FeatGainedRoot:        1,
		feature.FeatRaisedToRoot:      0,
		feature.FeatRaiseNoSession:    0,
		feature.FeatInteractiveOrigin: 1,
		feature.FeatHasTTY:            1,
		feature.FeatLineageDepth:      2,
		feature.FeatParentComm:        111,
	}
	if v := a.Score(normal); v.Score > 0.2 {
		t.Fatalf("normal score = %.2f, want <= 0.2", v.Score)
	}
}

func TestThinBaselineScoresLowerThanMature(t *testing.T) {
	attack := feature.Vector{
		feature.FeatRaiseNoSession:    1,
		feature.FeatRaisedToRoot:      1,
		feature.FeatInteractiveOrigin: 0,
	}
	thin := New(mustProfile(3))     // barely learned
	mature := New(mustProfile(100)) // well learned

	ts := thin.Score(attack).Score
	ms := mature.Score(attack).Score
	if !(ts < ms) {
		t.Fatalf("a thin baseline (%.2f) should score lower than a mature one (%.2f)", ts, ms)
	}
	if ts == 0 {
		t.Error("a partially-learned baseline should still register some signal")
	}
}

func mustProfile(n int) *baseline.Profile {
	p := baseline.NewProfile()
	normal := feature.Vector{
		feature.FeatRaiseNoSession:    0,
		feature.FeatRaisedToRoot:      0,
		feature.FeatInteractiveOrigin: 1,
	}
	for i := 0; i < n; i++ {
		for k, v := range normal {
			p.Observe(k, v)
		}
	}
	return p
}

// An override feature (fileless, ld_preload) must floor the score even when the
// attacker disguises everything else as a known program/parent, and must not
// inflate a normal exec where the flag is absent.
func TestOverrideFeatureFloorsScore(t *testing.T) {
	p := baseline.NewProfile()
	known := feature.Vector{
		feature.FeatExecPair:        222,
		feature.FeatExecChild:       333,
		feature.FeatExecInteractive: 1,
		feature.FeatExecFileless:    0,
		feature.FeatExecLdPreload:   0,
	}
	for i := 0; i < 100; i++ {
		for k, v := range known {
			p.Observe(k, v)
		}
	}
	a := New(p)

	// Evasive: identical known pair/child/interactive, but fileless is novel.
	evasive := feature.Vector{
		feature.FeatExecPair: 222, feature.FeatExecChild: 333, feature.FeatExecInteractive: 1,
		feature.FeatExecFileless: 1, feature.FeatExecLdPreload: 0,
	}
	if s := a.Score(evasive).Score; s < 0.9 {
		t.Fatalf("fileless with a known pair should floor high, got %.2f", s)
	}

	// A fully normal exec (flags absent) stays low — no dilution, no inflation.
	if s := a.Score(known).Score; s > 0.2 {
		t.Fatalf("normal exec should score low, got %.2f", s)
	}
}

// A no-session raise to root is an override feature, so it must floor the score
// high on its own even when every other provenance feature is disguised as this
// host's normal (known parent, usual lineage depth). Averaging would dilute the
// single sharpest compromise signal below the containment threshold and leave
// the graduated-response matrix's RaisedToRoot->Freeze branch unreachable — the
// exact gap a live experiment surfaced (it scored 0.64, under Contain=0.8).
func TestNoSessionRootRaiseFloorsScore(t *testing.T) {
	p := baseline.NewProfile()
	// Normal: root only ever reached interactively, from a familiar parent.
	normal := feature.Vector{
		feature.FeatGainedRoot: 1, feature.FeatRaisedToRoot: 0, feature.FeatRaiseNoSession: 0,
		feature.FeatInteractiveOrigin: 1, feature.FeatParentComm: 111, feature.FeatLineageDepth: 2,
	}
	for i := 0; i < 100; i++ {
		for k, v := range normal {
			p.Observe(k, v)
		}
	}
	a := New(p)
	// Evasive escalation: a familiar parent and the usual lineage depth, so every
	// averaged feature looks normal — only the no-session root raise is novel.
	evasive := feature.Vector{
		feature.FeatGainedRoot: 1, feature.FeatRaisedToRoot: 1, feature.FeatRaiseNoSession: 1,
		feature.FeatInteractiveOrigin: 0, feature.FeatParentComm: 111, feature.FeatLineageDepth: 2,
	}
	if s := a.Score(evasive).Score; s < 0.9 {
		t.Fatalf("a disguised no-session root raise should floor high (>=0.9), got %.2f", s)
	}
	// A service that routinely setuids to root with no session is learned away.
	for i := 0; i < 100; i++ {
		for k, v := range evasive {
			p.Observe(k, v)
		}
	}
	if s := New(p).Score(evasive).Score; s > 0.3 {
		t.Fatalf("a learned no-session root raise should not keep flooring, got %.2f", s)
	}
}

// A never-seen exec inside an interactive session (admin at a keyboard) must
// score lower than the same exec from a service (no session) — the RCE signal.
func TestInteractiveExecNoveltyIsDiscounted(t *testing.T) {
	p := baseline.NewProfile()
	for i := 0; i < 100; i++ {
		for _, interactive := range []float64{0, 1} {
			for k, v := range (feature.Vector{
				feature.FeatExecPair: 10, feature.FeatExecChild: 20, feature.FeatExecInteractive: interactive,
			}) {
				p.Observe(k, v)
			}
		}
	}
	a := New(p)
	mk := func(interactive float64) feature.Vector {
		return feature.Vector{feature.FeatExecPair: 999, feature.FeatExecChild: 888, feature.FeatExecInteractive: interactive}
	}
	si := a.Score(mk(1)).Score // interactive admin
	ss := a.Score(mk(0)).Score // service / no session
	if !(si < ss) {
		t.Fatalf("interactive novel exec (%.2f) should score below a service exec (%.2f)", si, ss)
	}
	if ss < 0.5 {
		t.Fatalf("a service spawning a never-seen program should still score high, got %.2f", ss)
	}
}

func TestEmptyBaselineIsNeutral(t *testing.T) {
	// With nothing learned, Surprise is 0 everywhere, so no false positives.
	a := New(baseline.NewProfile())
	v := a.Score(feature.Vector{feature.FeatRaiseNoSession: 1})
	if v.Score != 0 {
		t.Fatalf("empty-baseline score = %.2f, want 0", v.Score)
	}
}

// Each reason carries the arithmetic behind it, which the novelty row reports.
func TestReasonsCarryTheirTerms(t *testing.T) {
	p := baseline.NewProfile()
	for i := 0; i < 6; i++ {
		p.Observe(feature.FeatNetEgressPort, 443)
	}
	p.Observe(feature.FeatNetEgressPort, 22)
	v := New(p).Score(feature.Vector{feature.FeatNetEgressPort: 22})
	if len(v.Reasons) != 1 {
		t.Fatalf("reasons = %+v", v.Reasons)
	}
	r := v.Reasons[0]
	if r.Support != 1 || r.Samples != 7 || r.Surprise != 0.8 || r.Confidence != 7.0/15 {
		t.Errorf("terms = support %d samples %d surprise %v confidence %v", r.Support, r.Samples, r.Surprise, r.Confidence)
	}
}
