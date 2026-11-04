// Package baseline holds the learned model of a host's normal behavior. In
// learn mode Phage only updates this profile; in alert/enforce mode it is read
// to judge new events. The profile — not a hand-written rulebook — is the
// source of truth for what "normal" means on this host.
package baseline

import (
	"strconv"
	"sync"
)

// Profile is the per-host learned behavior. This first implementation keeps a
// frequency model per feature key: how often each value has been seen. It is
// intentionally simple and will be extended (co-occurrence, decay, continuous
// distributions) — see docs/design/analysis-engine.md.
type Profile struct {
	mu       sync.RWMutex
	counts   map[string]map[float64]uint64 // feature -> value -> times seen
	totals   map[string]uint64             // feature -> total observations
	overflow map[string]uint64             // feature -> new values refused at the cap
	max      int                           // distinct values per feature; 0 = unbounded
	gen      uint64                        // bumped by every change, so a checkpoint can skip an unchanged profile
}

// NewProfile returns an empty profile ready to learn, with no cap on distinct
// values (see SetMaxValuesPerKey).
func NewProfile() *Profile {
	return &Profile{
		counts:   make(map[string]map[float64]uint64),
		totals:   make(map[string]uint64),
		overflow: make(map[string]uint64),
	}
}

// SetMaxValuesPerKey caps how many distinct values one feature may learn (0:
// no cap). It bounds the baseline's memory and file size on a host where one
// feature is high-cardinality. A cap below what an imported baseline already
// holds keeps the learned values and refuses only new ones.
func (p *Profile) SetMaxValuesPerKey(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.max = n
}

// Observe records a feature value as normal. Called only in learn mode. It
// returns true when the value was refused because the feature already holds
// the maximum number of distinct values: the observation still counts towards
// the feature's total (so the feature stays learned), the value is not learned
// (so it stays novel), and the refusal is counted (Overflow).
func (p *Profile) Observe(key string, value float64) (overflow bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gen++
	byVal := p.counts[key]
	if byVal == nil {
		byVal = make(map[float64]uint64)
		p.counts[key] = byVal
	}
	p.totals[key]++
	if _, seen := byVal[value]; !seen && p.max > 0 && len(byVal) >= p.max {
		p.overflow[key]++
		return true
	}
	byVal[value]++
	return false
}

// Count reports how many times value was observed for key.
func (p *Profile) Count(key string, value float64) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.counts[key][value]
}

// Overflow reports the total number of values refused at the cap, over every
// feature (including refusals recorded in an imported baseline).
func (p *Profile) Overflow() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var n uint64
	for _, c := range p.overflow {
		n += c
	}
	return n
}

// Generation changes whenever the learned state changes.
func (p *Profile) Generation() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.gen
}

// establishedSupport is how many times a specific value must have been observed
// before Phage treats it as established "normal" for this host. Below it, the
// value is partially novel; at or above it, not surprising at all.
const establishedSupport = 5

// Surprise returns how unexpected (0..1) a feature value is given what has been
// learned. It measures *novelty*, not rarity: a value never seen before is
// maximally surprising (1.0); a value seen enough to be established is not
// surprising at all (0.0), no matter how small a share of the total it is.
//
// This distinction matters for high-cardinality features. A server runs many
// distinct parent->child pairs and talks to many ports; any one of them is a
// small fraction of all events, so a probability-share measure (1 - count/total)
// would brand even a pair seen hundreds of times as "surprising" and drown the
// real signal in noise. Novelty asks the question that actually matters — "have
// I seen this on this host, and enough to trust it?" — so only genuinely new
// behaviour (a service that never egressed suddenly dialing out) scores high.
//
// An unsampled feature is neutral (0) until it has been learned, so an empty
// baseline never fabricates anomalies.
func (p *Profile) Surprise(key string, value float64) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.totals[key] == 0 {
		return 0
	}
	seen := p.counts[key][value]
	if seen >= establishedSupport {
		return 0
	}
	return 1 - float64(seen)/float64(establishedSupport)
}

// Samples reports how many observations back a feature. Callers use it to tell
// "confidently normal" from "not yet learned".
func (p *Profile) Samples(key string) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.totals[key]
}

// Snapshot is the serialisable form of a Profile. Feature values are keyed by
// their decimal string so the counts survive JSON (which has no float keys).
type Snapshot struct {
	Counts   map[string]map[string]uint64 `json:"counts"`
	Totals   map[string]uint64            `json:"totals"`
	Overflow map[string]uint64            `json:"overflow,omitempty"` // values refused at the per-feature cap
}

// Export returns a serialisable copy of the learned state.
func (p *Profile) Export() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := Snapshot{
		Counts: make(map[string]map[string]uint64, len(p.counts)),
		Totals: make(map[string]uint64, len(p.totals)),
	}
	for key, byVal := range p.counts {
		m := make(map[string]uint64, len(byVal))
		for val, n := range byVal {
			m[strconv.FormatFloat(val, 'g', -1, 64)] = n
		}
		s.Counts[key] = m
	}
	for key, n := range p.totals {
		s.Totals[key] = n
	}
	if len(p.overflow) > 0 {
		s.Overflow = make(map[string]uint64, len(p.overflow))
		for key, n := range p.overflow {
			s.Overflow[key] = n
		}
	}
	return s
}

// Import replaces this profile's state with the snapshot's, in place, so any
// scorer already holding this *Profile sees the loaded data.
func (p *Profile) Import(s Snapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counts = make(map[string]map[float64]uint64, len(s.Counts))
	p.totals = make(map[string]uint64, len(s.Totals))
	for key, byVal := range s.Counts {
		m := make(map[float64]uint64, len(byVal))
		for valStr, n := range byVal {
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				continue
			}
			m[v] = n
		}
		p.counts[key] = m
	}
	for key, n := range s.Totals {
		p.totals[key] = n
	}
	p.overflow = make(map[string]uint64, len(s.Overflow))
	for key, n := range s.Overflow {
		p.overflow[key] = n
	}
	p.gen++
}
