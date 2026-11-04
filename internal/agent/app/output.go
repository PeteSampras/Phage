package app

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
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
// row identity, the dedupe emitter, and (unless output.novelty_path is empty)
// the sink file. Learn mode scores nothing, so it opens nothing.
func (a *App) openNovelty() error {
	if a.cfg.Mode == mode.Learn {
		return nil
	}
	o := a.cfg.Output
	entity := o.Entity
	if entity == "" { // kind host (config validation requires an entity otherwise)
		h, err := a.hostname()
		if err != nil {
			return fmt.Errorf("output.entity: read the host name: %w (set output.entity)", err)
		}
		if err := config.ValidateEntity(o.EntityKind, h, false); err != nil {
			return fmt.Errorf("output.entity: the host name %q cannot name this host: %w", h, err)
		}
		entity = h
	}
	a.ident = novelty.Identity{Source: o.Source, EntityKind: o.EntityKind, Entity: entity, TLP: o.TLP, Bucket: o.NoveltyBucket}
	var w *novelty.Sink
	if o.NoveltyPath != "" {
		s, err := novelty.OpenSink(o.NoveltyPath, o.NoveltyMaxBytes)
		if err != nil {
			return err
		}
		w, a.sink = s, s
		log.Printf("novelty sink %s: source=%s entity=%s:%s tlp=%s (rows are advisory: source_kind heuristic)",
			o.NoveltyPath, o.Source, o.EntityKind, entity, o.TLP)
	} else {
		log.Printf("novelty sink disabled (output.novelty_path empty): findings are logged and audited only")
	}
	if w != nil {
		a.novelty = novelty.NewEmitter(w, o.NoveltyBucket, log.Printf)
	} else {
		// An untyped nil, not a nil *Sink: the emitter then only dedupes.
		a.novelty = novelty.NewEmitter(nil, o.NoveltyBucket, log.Printf)
	}
	return nil
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

	h := audit.Health{
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
		Features: a.armed, BaselineSHA256: a.baselineSHA(), Health: &h,
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
