package novelty

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/AzozzALFiras/Phage/internal/audit"
)

// Sink appends rows to a JSON-lines file, one row per line. The file is
// opened like the audit trail (audit.OpenAppendFile: O_APPEND|O_NOFOLLOW|
// O_CLOEXEC, created 0600, regular files only). With maxBytes > 0 it rotates
// by renaming the file to path+".1" (replacing an older one) and starting a
// new file; a log shipper that follows by name (the Wazuh agent does) picks up
// the new file. With maxBytes 0 it never rotates, and logrotate's
// copytruncate is safe because every write is O_APPEND.
type Sink struct {
	path     string
	maxBytes int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenSink opens (or creates) the sink at path.
func OpenSink(path string, maxBytes int64) (*Sink, error) {
	s := &Sink{path: path, maxBytes: maxBytes}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sink) open() error {
	f, err := audit.OpenAppendFile(s.path)
	if err != nil {
		return fmt.Errorf("open novelty sink %q: %w", s.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat novelty sink %q: %w", s.path, err)
	}
	s.f, s.size = f, fi.Size()
	return nil
}

// Write appends one row. Each row is written with a single write(2) on an
// O_APPEND descriptor, so a row is never interleaved with another.
func (s *Sink) Write(r Row) error {
	if !writableTLP(r.TLP) {
		return fmt.Errorf("novelty row %s: TLP %q is not one this sink writes (clear, green, amber, amber+strict)", r.UID, r.TLP)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		// A failed rotation left no file open: try again now.
		if err := s.open(); err != nil {
			return err
		}
	}
	if s.maxBytes > 0 && s.size > 0 && s.size+int64(len(b)) > s.maxBytes {
		// Re-read the size first: an external copytruncate may have reset it.
		if fi, err := s.f.Stat(); err == nil {
			s.size = fi.Size()
		}
		if s.size > 0 && s.size+int64(len(b)) > s.maxBytes {
			if err := s.rotate(); err != nil {
				return err
			}
		}
	}
	n, err := s.f.Write(b)
	s.size += int64(n)
	if err != nil {
		return fmt.Errorf("write novelty sink %q: %w", s.path, err)
	}
	return nil
}

func (s *Sink) rotate() error {
	s.f.Close()
	s.f = nil
	if err := os.Rename(s.path, s.path+".1"); err != nil {
		// Keep writing to the same file rather than lose rows.
		if oerr := s.open(); oerr != nil {
			return fmt.Errorf("rotate novelty sink %q: %v; reopen: %w", s.path, err, oerr)
		}
		return fmt.Errorf("rotate novelty sink %q: %w (kept appending to it)", s.path, err)
	}
	return s.open()
}

// Close closes the file.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Counters are an Emitter's counts since it was created.
type Counters struct {
	Rows       uint64 // rows written (burst rows included)
	Suppressed uint64 // repeats of a uid still remembered (the same finding again)
	OverCap    uint64 // new rows past a profile's per-bucket cap (a burst row stands for them)
	Bursts     uint64 // burst rows emitted
	Errors     uint64 // rows that could not be written
}

// writer is what an Emitter writes to (a *Sink, or a fake in tests).
type writer interface {
	Write(Row) error
}

// Emitter writes rows once per uid, bounds how many new rows one profile may
// write per uid bucket, counts what it did, and reports write failures loudly
// but without flooding the log: the first failure at once, then at most one
// line per errorEvery, each carrying the number of failures since the last
// line. A write failure never stops the daemon.
type Emitter struct {
	w      writer
	id     Identity
	maxPer int     // new rows per (status, profile, entity, bucket) before a burst row
	exempt float64 // findings scoring at or above this are never capped (0: none)
	logf   func(format string, args ...any)
	now    func() time.Time

	mu         sync.Mutex
	seen       map[string]time.Time // uid -> when first emitted
	perBucket  map[bucketKey]int    // new rows per profile and bucket
	lastSweep  time.Time
	sweeps     uint64 // for tests: full scans of seen
	window     time.Duration
	c          Counters
	lastErrLog time.Time
	errsSince  uint64
}

type bucketKey struct {
	status, profile, entity string
	bucket                  int64
}

// ExemptFindingsAt exempts findings scoring at or above score (the contain
// threshold) from the per-bucket cap: noise must never hide a near-certain
// finding.
func (e *Emitter) ExemptFindingsAt(score float64) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.exempt = score
	e.mu.Unlock()
}

// maxSeen bounds the dedupe set. Past it, rows are written without dedupe
// (never dropped); the per-bucket cap still bounds them.
const maxSeen = 65536

// sweepEvery is the most often the dedupe set is scanned for expired uids:
// a scan of a full set is O(maxSeen), far too slow for every event.
const sweepEvery = time.Minute

// errorEvery is the minimum gap between two write-failure log lines.
const errorEvery = time.Minute

// NewEmitter returns an Emitter writing to w. id names the source and entity
// of the burst rows it writes and its Bucket is how long a uid is
// remembered; maxPerBucket caps the new rows per profile per bucket (0: no
// cap). logf receives failure lines. A nil w writes nothing and only dedupes
// and caps, so a caller can still log each new finding once.
func NewEmitter(w writer, id Identity, maxPerBucket int, logf func(string, ...any)) *Emitter {
	window := id.Bucket
	if window <= 0 {
		window = time.Hour
	}
	return &Emitter{w: w, id: id, maxPer: maxPerBucket, logf: logf, now: time.Now,
		seen: map[string]time.Time{}, perBucket: map[bucketKey]int{}, window: window}
}

// Emit writes r unless its uid is still remembered or its profile is past
// the per-bucket cap. The first row past the cap is replaced by one `burst`
// row carrying the count so far; later ones are only counted. It reports
// whether r itself was new and within the cap (written or attempted).
func (e *Emitter) Emit(r Row) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	now := e.now()
	if t, ok := e.seen[r.UID]; ok && now.Sub(t) < 2*e.window {
		e.c.Suppressed++
		e.mu.Unlock()
		return false
	}
	if now.Sub(e.lastSweep) >= sweepEvery {
		e.sweep(now)
	}
	if len(e.seen) < maxSeen {
		e.seen[r.UID] = now
	}
	out := r
	exempt := r.Status == StatusFinding && e.exempt > 0 && r.Score != nil && *r.Score >= e.exempt
	if e.maxPer > 0 && !exempt {
		// Findings and unlearned rows have separate budgets, so a flood of
		// one never hides the other.
		k := bucketKey{r.Status, r.Profile, r.Entity, r.bucket.Unix()}
		e.perBucket[k]++
		switch n := e.perBucket[k]; {
		case n == e.maxPer+1:
			out = e.id.Burst(r, n, now)
			e.c.OverCap++
			e.c.Bursts++
			if e.logf != nil {
				e.logf("NOVELTY BURST: more than %d new %s %s rows for %s:%s in the bucket starting %s; one burst row is written and the rest only counted (heartbeat novelty_over_cap)",
					e.maxPer, r.Status, r.Profile, r.EntityKind, r.Entity, Timestamp(r.bucket))
			}
		case n > e.maxPer+1:
			e.c.OverCap++
			e.mu.Unlock()
			return false
		}
	}
	e.mu.Unlock()
	if e.w == nil {
		return out.Status != StatusBurst
	}

	err := e.w.Write(out)

	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.c.Rows++
		return out.Status != StatusBurst
	}
	e.c.Errors++
	e.errsSince++
	delete(e.seen, r.UID) // a later repeat may succeed
	if e.lastErrLog.IsZero() || now.Sub(e.lastErrLog) >= errorEvery {
		e.logf("NOVELTY SINK WRITE FAILED (%d failure(s) since the last report; rows are being lost): %v", e.errsSince, err)
		e.lastErrLog, e.errsSince = now, 0
	}
	return out.Status != StatusBurst
}

// sweep drops expired uids and finished buckets. Called with e.mu held, at
// most once per sweepEvery.
func (e *Emitter) sweep(now time.Time) {
	e.lastSweep = now
	e.sweeps++
	for uid, t := range e.seen {
		if now.Sub(t) >= 2*e.window {
			delete(e.seen, uid)
		}
	}
	oldest := now.Add(-2 * e.window).Unix()
	for k := range e.perBucket {
		if k.bucket < oldest {
			delete(e.perBucket, k)
		}
	}
}

// Counters returns the counts so far.
func (e *Emitter) Counters() Counters {
	if e == nil {
		return Counters{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.c
}
