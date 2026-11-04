// Package behavioral is Phage's first Scorer: a statistical anomaly model that
// scores how far an event's features deviate from the host's learned baseline.
// It encodes no hardcoded attack rules — the baseline alone decides what is
// normal, which is what lets it flag exploits it has never seen before.
package behavioral

import (
	"fmt"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
)

// Anomaly scores feature vectors against a learned baseline profile.
type Anomaly struct {
	profile *baseline.Profile
	// weights lets some features matter more than others without changing the
	// model. Provenance features dominate because a missing session behind a
	// root transition is the strongest escalation signal we have.
	weights map[string]float64
}

// New returns an Anomaly scorer bound to a profile with sensible default
// weights.
func New(p *baseline.Profile) *Anomaly {
	return &Anomaly{
		profile: p,
		weights: map[string]float64{
			// privilege-change features. FeatRaiseNoSession — a raise to root with
			// no login session behind it — is the sharpest signal we have, so it is
			// an override feature (see overrideFeatures) that floors the score rather
			// than being averaged and diluted; it is not listed here.
			feature.FeatRaisedToRoot:      0.7, // unprivileged -> root
			feature.FeatInteractiveOrigin: 0.5,
			feature.FeatParentComm:        0.4, // an unusual parent for a root transition
			feature.FeatGainedRoot:        0.2,
			feature.FeatHasTTY:            0.2,
			// exec features. Fileless and ld_preload are override features (see
			// overrideFeatures): intrinsically anomalous when novel, so they floor
			// the score rather than being averaged in — they are not listed here.
			feature.FeatExecPair:        1.0, // a never-seen parent->child execution: the RCE effect
			feature.FeatExecInteractive: 0.4,
			feature.FeatExecChild:       0.3,
			// network (egress) features
			feature.FeatNetEgressComm:        1.0, // a program that never egresses dialing out: reverse shell / C2
			feature.FeatNetEgressPair:        0.8, // ...to a port it never uses
			feature.FeatNetEgressInteractive: 0.4,
			feature.FeatNetEgressPort:        0.3,
			// filesystem (persistence) features
			feature.FeatFileWritePair:        1.0, // a program writing a persistence class it never writes: the persistence effect
			feature.FeatFileWriteCategory:    0.6, // ...a class rarely written on this host at all
			feature.FeatFileWriteInteractive: 0.4,
			feature.FeatFileWriteComm:        0.3,
			// kernel-enabling features (exploit setup, pre-escalation)
			feature.FeatEnableCommOp:      1.0, // a program doing a high-risk enabling op it never does
			feature.FeatEnableOp:          0.5, // ...an op rarely done on this host at all
			feature.FeatEnableInteractive: 0.4,
		},
	}
}

// overrideFeatures are binary "red flags" whose mere presence (when novel for
// this host) indicates malice on its own — fileless execution, a dynamic-linker
// hijack, an unprivileged process reaching root with no login session behind it.
// They are scored as a floor on the verdict rather than averaged with the other
// features, so a single such flag is not diluted by many normal features, and it
// is caught even when the attacker disguises everything else (a known-looking
// program and parent). It stays behavioural: a flag the host sets legitimately
// is learned (surprise 0) and floors nothing — a service that routinely setuids
// to root with no session is learned away, and an interactive sudo never sets
// the no-session flag at all.
var overrideFeatures = map[string]bool{
	feature.FeatExecFileless:   true,
	feature.FeatExecLdPreload:  true,
	feature.FeatRaiseNoSession: true,
}

// Score implements scorer.Scorer. The score is the weighted, baseline-relative
// surprise of the event's features (plus any override-feature floor); each
// surprising feature records a reason so the verdict can always explain itself.
func (a *Anomaly) Score(v feature.Vector) verdict.Verdict {
	out := verdict.Verdict{}
	if a.profile == nil {
		return out
	}
	// The RCE signal is a *service* spawning a never-seen program. A novel exec
	// inside an interactive login session is a human running new commands, which
	// is expected — so its parent->child novelty is discounted. The no-session
	// (service) case keeps full weight, so RCE detection is untouched while benign
	// admin activity stops generating false positives (see docs/benchmark).
	interactiveExec := v[feature.FeatExecInteractive] == 1

	var score, weightSum, floor float64
	for key, val := range v {
		s := a.profile.Surprise(key, val)
		samples := a.profile.Samples(key)
		// Discount surprise from features not yet observed enough times to trust,
		// so a freshly-deployed agent never raises confident alerts off a thin
		// baseline; mature features (>= minConfidentSamples) are unaffected.
		conf := confidence(samples)
		support := a.profile.Count(key, val)
		// A value refused at the per-feature cap was never learned, whatever
		// the host did: trust its novelty less, and say why.
		capped := s > 0 && support == 0 && a.profile.AtCap(key)
		if capped {
			conf *= cappedConfidence
		}
		terms := verdict.Reason{Surprise: s, Confidence: conf, Support: support, Samples: samples}

		if overrideFeatures[key] {
			// Floor the score by the flag's own learned surprise; keep it out of
			// the averaging denominator so it neither dilutes nor is diluted.
			if s <= 0 {
				continue
			}
			f := s * conf
			if f > floor {
				floor = f
			}
			r := terms
			r.Feature, r.Contribution, r.Detail = key, f, detail(key, val, s, capped)
			out.Reasons = append(out.Reasons, r)
			continue
		}

		w := a.weight(key)
		weightSum += w
		if s <= 0 {
			continue
		}
		contribution := w * s * conf
		if interactiveExec && (key == feature.FeatExecPair || key == feature.FeatExecChild) {
			contribution *= execInteractiveDiscount
		}
		if contribution <= 0 {
			continue
		}
		score += contribution
		r := terms
		r.Feature, r.Contribution, r.Detail = key, contribution, detail(key, val, s, capped)
		out.Reasons = append(out.Reasons, r)
	}
	if weightSum > 0 {
		score /= weightSum
	}
	if floor > score {
		score = floor
	}
	out.Score = clamp01(score)
	return out
}

// minConfidentSamples is how many observations a feature needs before Phage
// trusts its surprise fully. Below it, a feature's contribution is scaled down
// linearly, so "I have barely seen this" never reads as "this is an attack".
const minConfidentSamples = 15

// execInteractiveDiscount scales down exec parent->child novelty when the exec
// happens inside an interactive login session (expected admin activity), so it
// does not dominate the score. Service (no-session) execs are not discounted.
const execInteractiveDiscount = 0.3

// cappedConfidence discounts a value that is novel only in the sense that the
// feature had reached learn.max_values_per_key and could learn no more.
const cappedConfidence = 0.5

func detail(key string, val, surprise float64, capped bool) string {
	d := explain(key, val, surprise)
	if capped {
		d += " [feature at cap; value not learned]"
	}
	return d
}

func confidence(samples uint64) float64 {
	if samples >= minConfidentSamples {
		return 1
	}
	return float64(samples) / float64(minConfidentSamples)
}

func (a *Anomaly) weight(key string) float64 {
	if w, ok := a.weights[key]; ok {
		return w
	}
	return 0.1 // unknown features still count a little
}

// explain renders a human reason. It describes the deviation, never a verdict.
func explain(key string, val, surprise float64) string {
	switch key {
	case feature.FeatExecFileless:
		if val == 1 {
			return "executed from an anonymous in-memory file (fileless) — no program on disk"
		}
	case feature.FeatExecLdPreload:
		if val == 1 {
			return "launched with a dynamic-linker hijack in its environment (LD_PRELOAD / LD_AUDIT / GLIBC_TUNABLES)"
		}
	case feature.FeatExecPair:
		return "a program was spawned in a parent->child combination never seen on this host"
	case feature.FeatExecInteractive:
		if val == 0 {
			return "program launched by a service with no interactive session"
		}
	case feature.FeatNetEgressComm:
		return "an outbound connection from a program that has never egressed on this host"
	case feature.FeatNetEgressPair:
		return "an outbound connection to a destination port this program never uses"
	case feature.FeatNetEgressInteractive:
		if val == 0 {
			return "outbound connection from a process with no interactive session"
		}
	case feature.FeatFileWritePair:
		return "a program wrote a persistence/credential file class it has never written on this host"
	case feature.FeatFileWriteCategory:
		return "a write to a persistence/credential file class rarely seen on this host"
	case feature.FeatFileWriteInteractive:
		if val == 0 {
			return "persistence-relevant file written by a process with no interactive session"
		}
	case feature.FeatEnableCommOp:
		return "a program performed a high-risk kernel-enabling operation it has never performed on this host"
	case feature.FeatEnableOp:
		return "a high-risk kernel-enabling operation rarely performed on this host"
	case feature.FeatEnableInteractive:
		if val == 0 {
			return "high-risk kernel operation from a process with no interactive session"
		}
	case feature.FeatRaiseNoSession:
		if val == 1 {
			return "raised to root with no login session behind it (never seen on this host)"
		}
	case feature.FeatRaisedToRoot:
		if val == 1 {
			return "an unprivileged process raised itself to root"
		}
	case feature.FeatInteractiveOrigin:
		if val == 0 {
			return "privilege change with no interactive session behind it"
		}
	case feature.FeatGainedRoot:
		if val == 1 {
			return "process gained root"
		}
	}
	return fmt.Sprintf("%s=%g is unusual for this host (surprise %.2f)", key, val, surprise)
}

func clamp01(f float64) float64 {
	switch {
	case f < 0:
		return 0
	case f > 1:
		return 1
	default:
		return f
	}
}
