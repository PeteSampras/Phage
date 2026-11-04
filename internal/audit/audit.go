// Package audit records every response Phage takes as an append-only JSON-lines
// trail. An auto-response you cannot review after the fact is one no operator
// will trust; this is that review trail.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Record kinds, so a SIEM can route on them.
const (
	KindResponse         = "response"          // a verdict, what the matrix asked for, and what was done
	KindStartup          = "startup"           // every start: mode, what armed, config provenance
	KindEnforcementArmed = "enforcement_armed" // startup, when any host-modifying feature was requested
	KindDisarmed         = "disarmed"          // startup, when a -mode downgrade switched features off
	KindSelfHeal         = "self_heal"         // one self-heal attempt: healed | unchanged | failed:<err>
)

// Startup status values.
const (
	StatusArmed  = "armed"  // at least one requested host-modifying feature armed
	StatusFailed = "failed" // features were requested but none armed
	StatusNone   = "none"   // nothing host-modifying was requested
)

// Entry is one recorded event. Response records use Requested/Action/Outcome;
// startup records use the provenance and feature fields.
type Entry struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind,omitempty"`
	Requested string    `json:"requested,omitempty"` // the rung the response matrix chose
	Action    string    `json:"action"`              // the rung actually applied
	Outcome   string    `json:"outcome,omitempty"`   // contained | notified | skipped:<why> | failed:<err>
	Score     float64   `json:"score"`
	PID       int32     `json:"pid"`
	Comm      string    `json:"comm"`
	Reason    string    `json:"reason"`
	Path      string    `json:"path,omitempty"`     // self_heal: the sentinel healed
	Evidence  string    `json:"evidence,omitempty"` // self_heal: where the tampered version was kept

	Status       string   `json:"status,omitempty"`
	Mode         string   `json:"mode,omitempty"`
	Version      string   `json:"version,omitempty"`
	ConfigPath   string   `json:"config_path,omitempty"`
	ConfigSHA256 string   `json:"config_sha256,omitempty"`
	Features     []string `json:"features,omitempty"` // host-modifying features that armed
	Failed       []string `json:"failed,omitempty"`   // requested but not armed
	Disarmed     []string `json:"disarmed,omitempty"` // switched off by a -mode downgrade
}

// Writer appends entries to a file. A nil *Writer is valid and discards writes,
// so auditing can be left disabled (learn/alert without host-modifying
// features) without nil checks at the call site.
type Writer struct {
	mu sync.Mutex
	f  *os.File
}

// Open returns a Writer appending to path, created 0600. The final component
// is opened O_NOFOLLOW so a planted symlink cannot redirect root's appends,
// O_NONBLOCK so a FIFO planted there fails instead of hanging startup, only a
// regular file is accepted, and a pre-existing file with looser permissions is
// tightened. An empty path
// disables auditing (nil *Writer).
func Open(path string) (*Writer, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit trail directory: %w", err)
	}
	const flags = os.O_WRONLY | os.O_APPEND | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	// A new trail is created 0600 exclusively, so its mode comes from the
	// create alone; only a pre-existing trail is vetted and tightened.
	f, err := os.OpenFile(path, flags|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		f, err = openExisting(path, flags)
	}
	if err != nil {
		return nil, fmt.Errorf("open audit trail %q: %w", path, err)
	}
	return &Writer{f: f}, nil
}

func openExisting(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, fmt.Errorf("tighten to 0600: %w", err)
		}
	}
	return f, nil
}

// ErrDisabled is returned by Record on a nil Writer.
var ErrDisabled = errors.New("audit trail disabled")

// Record appends one entry. Time is set if the caller left it zero. Callers
// for whom the record is mandatory (startup / arming) treat an error as fatal.
func (w *Writer) Record(e Entry) error {
	if w == nil || w.f == nil {
		return ErrDisabled
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// Sync flushes the trail to disk.
func (w *Writer) Sync() error {
	if w == nil || w.f == nil {
		return ErrDisabled
	}
	return w.f.Sync()
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	return w.f.Close()
}
