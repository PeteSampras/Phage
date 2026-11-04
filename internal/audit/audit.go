// Package audit records every response Phage takes as an append-only JSON-lines
// trail. An auto-response you cannot review after the fact is one no operator
// will trust; this is that review trail.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event kinds an Entry can carry, so a SIEM can route on them.
const (
	KindResponse         = "response"          // a verdict and the action taken on it
	KindEnforcementArmed = "enforcement_armed" // startup: acting features armed in this run
)

// Entry is one recorded action.
type Entry struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind,omitempty"`
	Action   string    `json:"action"`
	Score    float64   `json:"score"`
	PID      int32     `json:"pid"`
	Comm     string    `json:"comm"`
	Reason   string    `json:"reason"`
	Mode     string    `json:"mode,omitempty"`
	Features []string  `json:"features,omitempty"` // enforcement_armed: features that armed
	Failed   []string  `json:"failed,omitempty"`   // enforcement_armed: features requested but not armed
}

// Writer appends entries to a file. A nil *Writer is valid and discards writes,
// so auditing can be left disabled without nil checks at the call site.
type Writer struct {
	mu sync.Mutex
	f  *os.File
}

// Open returns a Writer appending to path. An empty path disables auditing
// (returns a nil *Writer, which is safe to use).
func Open(path string) (*Writer, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &Writer{f: f}, nil
}

// Record appends one entry. Time is set if the caller left it zero.
func (w *Writer) Record(e Entry) {
	if w == nil || w.f == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.f.Write(append(b, '\n'))
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	return w.f.Close()
}
