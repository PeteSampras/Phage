package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// Established reports whether a value seen n times is normal for its feature
// (it scores no surprise). Exposed for reports.
func Established(n uint64) bool { return n >= establishedSupport }

// ParseSnapshot reads a baseline file's bytes. It is what the daemon's loader
// and the read-only `phage baseline` commands both accept.
func ParseSnapshot(b []byte) (Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// KeySummary describes one feature key of a baseline.
type KeySummary struct {
	Key         string
	Total       uint64 // observations
	Distinct    int    // distinct values learned
	Established int    // values seen often enough to score no surprise
	Overflow    uint64 // new values refused at the per-feature cap
}

// Summarize lists every feature key of a snapshot, sorted by key.
func Summarize(s Snapshot) []KeySummary {
	keys := map[string]bool{}
	for k := range s.Counts {
		keys[k] = true
	}
	for k := range s.Totals {
		keys[k] = true
	}
	for k := range s.Overflow {
		keys[k] = true
	}
	out := make([]KeySummary, 0, len(keys))
	for k := range keys {
		ks := KeySummary{Key: k, Total: s.Totals[k], Distinct: len(s.Counts[k]), Overflow: s.Overflow[k]}
		for _, n := range s.Counts[k] {
			if Established(n) {
				ks.Established++
			}
		}
		out = append(out, ks)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// KeyDiff is how one feature key changed between two baselines.
type KeyDiff struct {
	Key                 string
	Old, New            KeySummary
	Added               []string // values learned in new and absent from old
	Removed             []string // values in old and absent from new
	NewlyEstablished    []string // values that will no longer alert (crossed the support bar)
	NoLongerEstablished []string // values that will alert again
}

// Changed reports whether anything about the key differs.
func (d KeyDiff) Changed() bool {
	return d.Old != d.New || len(d.Added)+len(d.Removed)+len(d.NewlyEstablished)+len(d.NoLongerEstablished) > 0
}

// Diff compares two baselines key by key (sorted by key; unchanged keys are
// left out). Values are printed as the baseline stores them: ports and flags
// as numbers, program and pair names as their stable hash ids.
func Diff(oldS, newS Snapshot) []KeyDiff {
	o, n := byKey(Summarize(oldS)), byKey(Summarize(newS))
	keys := map[string]bool{}
	for k := range o {
		keys[k] = true
	}
	for k := range n {
		keys[k] = true
	}
	var out []KeyDiff
	for k := range keys {
		d := KeyDiff{Key: k, Old: o[k], New: n[k]}
		d.Old.Key, d.New.Key = k, k
		oc, nc := oldS.Counts[k], newS.Counts[k]
		for v, c := range nc {
			oldC, had := oc[v]
			if !had {
				d.Added = append(d.Added, v)
			}
			if Established(c) && !Established(oldC) {
				d.NewlyEstablished = append(d.NewlyEstablished, v)
			}
		}
		for v, c := range oc {
			newC, has := nc[v]
			if !has {
				d.Removed = append(d.Removed, v)
			}
			if Established(c) && !Established(newC) {
				d.NoLongerEstablished = append(d.NoLongerEstablished, v)
			}
		}
		for _, l := range [][]string{d.Added, d.Removed, d.NewlyEstablished, d.NoLongerEstablished} {
			sortValues(l)
		}
		if d.Changed() {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func byKey(l []KeySummary) map[string]KeySummary {
	m := make(map[string]KeySummary, len(l))
	for _, ks := range l {
		m[ks.Key] = ks
	}
	return m
}

// sortValues orders value strings numerically where they parse, so a list of
// ports reads in order.
func sortValues(l []string) {
	sort.Slice(l, func(i, j int) bool {
		a, ea := strconv.ParseFloat(l[i], 64)
		b, eb := strconv.ParseFloat(l[j], 64)
		if ea == nil && eb == nil && a != b {
			return a < b
		}
		return l[i] < l[j]
	})
}

// WriteSummary prints a snapshot's keys as a table.
func WriteSummary(w io.Writer, s Snapshot) {
	fmt.Fprintf(w, "%-28s %12s %9s %12s %9s\n", "feature", "observations", "distinct", "established", "overflow")
	for _, ks := range Summarize(s) {
		fmt.Fprintf(w, "%-28s %12d %9d %12d %9d\n", ks.Key, ks.Total, ks.Distinct, ks.Established, ks.Overflow)
	}
}

// WriteDiff prints a diff, listing at most maxValues values per list (0: all).
func WriteDiff(w io.Writer, diffs []KeyDiff, maxValues int) {
	if len(diffs) == 0 {
		fmt.Fprintln(w, "no differences")
		return
	}
	for _, d := range diffs {
		fmt.Fprintf(w, "%s\n", d.Key)
		fmt.Fprintf(w, "  observations %d -> %d, distinct %d -> %d, established %d -> %d, overflow %d -> %d\n",
			d.Old.Total, d.New.Total, d.Old.Distinct, d.New.Distinct, d.Old.Established, d.New.Established,
			d.Old.Overflow, d.New.Overflow)
		for _, l := range []struct {
			name string
			vals []string
		}{
			{"added", d.Added},
			{"removed", d.Removed},
			{"newly established (will no longer alert)", d.NewlyEstablished},
			{"no longer established (will alert again)", d.NoLongerEstablished},
		} {
			if len(l.vals) == 0 {
				continue
			}
			shown := l.vals
			if maxValues > 0 && len(shown) > maxValues {
				shown = shown[:maxValues]
			}
			fmt.Fprintf(w, "  %s (%d): %v", l.name, len(l.vals), shown)
			if len(shown) < len(l.vals) {
				fmt.Fprintf(w, " ... and %d more", len(l.vals)-len(shown))
			}
			fmt.Fprintln(w)
		}
	}
}
