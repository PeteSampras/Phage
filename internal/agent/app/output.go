package app

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/novelty"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
)

// This file holds what phaged reports for other systems: novelty_finding rows
// (alert and enforce), the heartbeat record (every mode), and the learn-mode
// baseline checkpoint. None of it acts on the host.

// openNovelty prepares the novelty output for alert and enforce mode: the
// row identity, the emitter (dedupe and per-bucket cap) and, when
// output.novelty_path is set (opt-in), the sink file. Learn mode scores
// nothing, so it opens nothing. Config validation has already required
// output.tlp, output.entity_kind and output.entity for a sink.
func (a *App) openNovelty() error {
	if a.cfg.Mode == mode.Learn {
		return nil
	}
	o := a.cfg.Output
	a.ident = novelty.Identity{Source: o.Source, EntityKind: o.EntityKind, Entity: o.Entity, TLP: o.TLP, Bucket: o.NoveltyBucket}
	if o.NoveltyPath == "" {
		log.Printf("novelty sink off (output.novelty_path unset): findings are logged and audited only")
		// An untyped nil, not a nil *Sink: the emitter then only dedupes and caps.
		a.novelty = novelty.NewEmitter(nil, a.ident, o.NoveltyMaxPerBucket, log.Printf)
		return nil
	}
	s, err := novelty.OpenSink(o.NoveltyPath, o.NoveltyMaxBytes)
	if err != nil {
		return err
	}
	a.sink = s
	a.novelty = novelty.NewEmitter(s, a.ident, o.NoveltyMaxPerBucket, log.Printf)
	log.Printf("novelty sink %s: source=%s entity=%s:%s tlp=%s, at most %d new rows per profile per %s (rows are advisory: source_kind heuristic)",
		o.NoveltyPath, o.Source, o.EntityKind, o.Entity, o.TLP, o.NoveltyMaxPerBucket, o.NoveltyBucket)
	return nil
}

// Baseline states, as the startup and heartbeat records and phage status
// report them.
const (
	baselineNone    = "no_baseline" // no observation at all
	baselineWarming = "warming"     // fewer than learn.min_baseline_samples observations
	baselineReady   = "ready"
)

// baselineState classifies the baseline by its total feature observations.
// The result is cached per profile generation (the baseline does not change
// outside learn mode).
func (a *App) baselineState() (string, uint64) {
	gen := a.profile.Generation()
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.stateKnown || gen != a.stateGen {
		n := a.profile.Observations()
		switch {
		case n == 0:
			a.state = baselineNone
		case n < a.cfg.Learn.MinBaselineSamples:
			a.state = baselineWarming
		default:
			a.state = baselineReady
		}
		a.stateKnown, a.stateGen, a.stateSamples = true, gen, n
	}
	return a.state, a.stateSamples
}

// announceBaseline logs the baseline state at startup, loudly when it is not
// ready outside learn mode.
func (a *App) announceBaseline() {
	state, n := a.baselineState()
	if state == baselineReady || a.cfg.Mode == mode.Learn {
		log.Printf("baseline state=%s (%d feature observations; ready at %d)", state, n, a.cfg.Learn.MinBaselineSamples)
		return
	}
	log.Printf("BASELINE NOT READY state=%s: %d feature observations, below learn.min_baseline_samples=%d, in %s mode — "+
		"scores off a thin baseline are discounted and never-seen feature classes are NOT reported as unlearned; run learn mode longer",
		state, n, a.cfg.Learn.MinBaselineSamples, a.cfg.Mode)
}

// baselineSHA names the baseline in use: the sha256 of the file as loaded or
// last saved, or "none".
func (a *App) baselineSHA() string {
	if a.store == nil {
		return "none"
	}
	return a.store.Digest()
}

// unlearnedKeys returns the event's feature keys when NONE of them has a
// single observation in the baseline: the whole feature class (every key the
// event's extractor produced) was never seen while learning. The scorer treats
// an unobserved feature as neutral, so such an event would score 0 and stay
// silent; it is reported as unlearned instead. A class with any observation
// is scored as before.
func (a *App) unlearnedKeys(vec feature.Vector) []string {
	if len(vec) == 0 {
		return nil
	}
	// With no (or too thin a) baseline everything is unlearned, and a row per
	// event would flood the sink and make this host corroborate everything.
	if state, _ := a.baselineState(); state != baselineReady {
		return nil
	}
	keys := make([]string, 0, len(vec))
	for k := range vec {
		if a.profile.Samples(k) > 0 {
			return nil
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// reportUnlearned logs an event whose feature class has no baseline (once per
// uid bucket) and writes its unlearned row. It is never a verdict: no score,
// no response, no audit response record.
func (a *App) reportUnlearned(ev model.Event, keys []string) {
	a.mu.Lock()
	a.nUnlearned++
	a.mu.Unlock()
	if a.novelty == nil {
		return
	}
	row := a.ident.Unlearned(ev, keys, a.baselineSHA(), time.Now())
	if a.novelty.Emit(row) {
		log.Printf("UNLEARNED kind=%s value=%q pid=%d comm=%q :: never seen while learning (%d feature(s) with no baseline) — not scored",
			ev.Kind, row.Value, ev.PID, ev.Comm, len(keys))
	}
}

// lagStats accumulates the enrichment lag between heartbeats.
type lagStats struct {
	n        uint64
	sum, max time.Duration
}

// noteLag measures how long an event took from the kernel's timestamp to now
// (ring-buffer queueing, decoding and /proc enrichment) and back-dates the
// event's time by it, so a row's `time` is when the kernel saw the event.
func (a *App) noteLag(ev *model.Event) {
	if ev.KernelNs == 0 || a.monoNow == nil {
		return
	}
	now, ok := a.monoNow()
	if !ok || now < ev.KernelNs {
		return
	}
	lag := time.Duration(now - ev.KernelNs)
	ev.Time = time.Now().Add(-lag)
	a.mu.Lock()
	a.lag.n++
	a.lag.sum += lag
	if lag > a.lag.max {
		a.lag.max = lag
	}
	a.mu.Unlock()
}

// heartbeatState is what the previous heartbeat saw, so the next one reports
// the interval in between. Only the heartbeat goroutine touches it, except
// last (read by Status under a.mu).
type heartbeatState struct {
	at        time.Time
	events    uint64
	drops     uint64
	dropsSeen bool
	novelty   novelty.Counters
	last      *audit.Health
	lastAt    time.Time
}

func (a *App) heartbeatLoop(ctx context.Context) {
	every := time.Duration(a.cfg.Output.HeartbeatInterval) * time.Second
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.heartbeat(now)
		}
	}
}

// heartbeat writes one `heartbeat` audit record: events/s, ring-buffer drops
// since the last heartbeat (and in total), enrichment lag, novelty sink
// counts, mode, armed features and the baseline's sha256. A SIEM alerts on
// drops, and on the heartbeat going missing (docs/wazuh.md). A failed write is
// logged, not fatal: the missing heartbeat is itself the alert.
func (a *App) heartbeat(now time.Time) audit.Entry {
	if a.hb.at.IsZero() {
		a.hb.at = a.started
	}
	elapsed := now.Sub(a.hb.at).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	a.hb.at = now

	a.mu.Lock()
	events := a.nEvents - a.hb.events
	a.hb.events = a.nEvents
	lag := a.lag
	a.lag = lagStats{}
	ckptErrors := a.ckptErrors
	a.mu.Unlock()

	state, samples := a.baselineState()
	h := audit.Health{
		BaselineState:    state,
		BaselineSamples:  samples,
		IntervalSeconds:  round2(elapsed),
		Events:           events,
		EventsPerSec:     round2(float64(events) / elapsed),
		BaselineOverflow: a.profile.Overflow(),
		CheckpointErrors: ckptErrors,
	}
	if lag.n > 0 {
		h.EnrichLagMsAvg = round2(float64(lag.sum) / float64(lag.n) / 1e6)
		h.EnrichLagMsMax = round2(float64(lag.max) / 1e6)
	}
	if a.drops == nil {
		h.DropsError = "sensor not loaded"
	} else if total, err := a.drops(); err != nil {
		h.DropsError = err.Error()
	} else {
		h.DropsTotal = total
		if a.hb.dropsSeen && total >= a.hb.drops {
			h.Drops = total - a.hb.drops
		} else {
			h.Drops = total // first reading: everything since the sensors loaded
		}
		a.hb.drops, a.hb.dropsSeen = total, true
	}
	c := a.novelty.Counters()
	h.NoveltyRows = c.Rows - a.hb.novelty.Rows
	h.NoveltySuppressed = c.Suppressed - a.hb.novelty.Suppressed
	h.NoveltyOverCap = c.OverCap - a.hb.novelty.OverCap
	h.NoveltyErrors = c.Errors - a.hb.novelty.Errors
	a.hb.novelty = c

	if h.Drops > 0 {
		log.Printf("SENSOR DROPS: %d event(s) lost in the last %.0fs (ring buffer full; %d since start) — detection is incomplete",
			h.Drops, elapsed, h.DropsTotal)
	}
	if h.DropsError != "" && a.drops != nil {
		log.Printf("heartbeat: cannot read the ring-buffer drop counter: %s", h.DropsError)
	}

	e := audit.Entry{
		Time: now, Kind: audit.KindHeartbeat, Action: audit.KindHeartbeat,
		PID: a.selfPID, Comm: "phaged", Mode: a.cfg.Mode.String(), Version: a.meta.Version,
		Features: a.armed, BaselineSHA256: a.baselineSHA(), BaselineState: state, Health: &h,
		Reason: fmt.Sprintf("heartbeat: %.2f events/s, %d drop(s), enrichment lag avg %.2fms max %.2fms",
			h.EventsPerSec, h.Drops, h.EnrichLagMsAvg, h.EnrichLagMsMax),
	}
	if err := a.audit.Record(e); err != nil && err != audit.ErrDisabled {
		log.Printf("audit: heartbeat: %v", err)
	}
	a.mu.Lock()
	a.hb.last, a.hb.lastAt = &h, now
	a.mu.Unlock()
	return e
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// checkpointLoop saves the baseline every learn.checkpoint_interval while
// learning, so a crash or power loss loses at most one interval of learning
// (the shutdown save covers a clean stop).
func (a *App) checkpointLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.Learn.CheckpointInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.checkpoint()
		}
	}
}

// checkpoint saves the baseline if it changed since the last save. A failure
// is logged loudly and counted (heartbeat checkpoint_errors); the next
// interval tries again.
func (a *App) checkpoint() {
	a.saveMu.Lock()
	unchanged := a.profile.Generation() == a.savedGen
	a.saveMu.Unlock()
	if unchanged {
		return
	}
	if err := a.saveBaseline(); err != nil {
		a.mu.Lock()
		a.ckptErrors++
		a.mu.Unlock()
		log.Printf("BASELINE CHECKPOINT FAILED: %v — learning since the last good save would be lost in a crash", err)
		return
	}
	log.Printf("baseline checkpoint saved sha256=%s", a.store.Digest())
}

// saveBaseline writes the baseline atomically (temp file + rename), one save
// at a time.
func (a *App) saveBaseline() error {
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	gen := a.profile.Generation() // taken before the export: a change during the save is saved next time
	if err := a.store.Save(a.profile); err != nil {
		return err
	}
	a.savedGen = gen
	return nil
}
