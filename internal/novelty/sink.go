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
	Rows       uint64 // rows written
	Suppressed uint64 // repeats of a uid already written in its bucket
	Errors     uint64 // rows that could not be written
}

// writer is what an Emitter writes to (a *Sink, or a fake in tests).
type writer interface {
	Write(Row) error
}

// Emitter writes rows once per uid, counts what it did, and reports write
// failures loudly but without flooding the log: the first failure at once,
// then at most one line per errorEvery, each carrying the number of failures
// since the last line. A write failure never stops the daemon.
type Emitter struct {
	w    writer
	logf func(format string, args ...any)
	now  func() time.Time

	mu         sync.Mutex
	seen       map[string]time.Time // uid -> when written, for the current dedupe window
	window     time.Duration
	c          Counters
	lastErrLog time.Time
	errsSince  uint64
}

// maxSeen bounds the dedupe set. Past it, rows are written without dedupe
// (never dropped): a flood of distinct findings is itself worth seeing.
const maxSeen = 65536

// errorEvery is the minimum gap between two write-failure log lines.
const errorEvery = time.Minute

// NewEmitter returns an Emitter writing to w. window is how long a uid is
// remembered (the uid bucket). logf receives failure lines. A nil w writes
// nothing and only dedupes, so a caller can still log each new finding once.
func NewEmitter(w writer, window time.Duration, logf func(string, ...any)) *Emitter {
	return &Emitter{w: w, logf: logf, now: time.Now, seen: map[string]time.Time{}, window: window}
}

// Emit writes r unless its uid was already written within the window. It
// reports whether the row was new (written or attempted).
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
	if len(e.seen) >= maxSeen {
		for uid, t := range e.seen {
			if now.Sub(t) >= 2*e.window {
				delete(e.seen, uid)
			}
		}
	}
	if len(e.seen) < maxSeen {
		e.seen[r.UID] = now
	}
	e.mu.Unlock()
	if e.w == nil {
		return true // no sink: dedupe only (it still rate-limits the log line)
	}

	err := e.w.Write(r)

	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.c.Rows++
		return true
	}
	e.c.Errors++
	e.errsSince++
	delete(e.seen, r.UID) // a later repeat may succeed
	if e.lastErrLog.IsZero() || now.Sub(e.lastErrLog) >= errorEvery {
		e.logf("NOVELTY SINK WRITE FAILED (%d failure(s) since the last report; rows are being lost): %v", e.errsSince, err)
		e.lastErrLog, e.errsSince = now, 0
	}
	return true
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
