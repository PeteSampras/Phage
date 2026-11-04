// Package verdict is the explainable output of the analysis pipeline: a score
// plus the human-readable reasons behind it. Explainability is a first-class
// requirement, not an afterthought — an auto-response nobody can explain is one
// nobody will trust in enforce mode.
package verdict

// Reason explains one contribution to the score.
type Reason struct {
	Feature      string  // feature key from internal/analysis/feature
	Contribution float64 // how much this pushed the score up
	Detail       string  // human sentence, e.g. "root gained with no interactive session"

	// The arithmetic behind Contribution, for reporting (novelty rows). Zero
	// when the reason is intrinsic rather than learned (self-defense,
	// honeytoken), which set Confidence 1 themselves.
	Surprise   float64 // 0..1: how novel the value is for this host
	Confidence float64 // 0..1: how much the baseline behind the feature is trusted
	Support    uint64  // times the value was observed while learning
	Samples    uint64  // observations of the feature while learning
}

// Verdict is produced per event by a Scorer. Score is normalised to 0.0
// (normal) .. 1.0 (certainly anomalous). The policy layer, not this package,
// turns a score into an action.
type Verdict struct {
	Score   float64
	Reasons []Reason
}

// Top returns the most significant reason, or a zero Reason if there are none.
func (v Verdict) Top() Reason {
	var top Reason
	for _, r := range v.Reasons {
		if r.Contribution > top.Contribution {
			top = r
		}
	}
	return top
}
