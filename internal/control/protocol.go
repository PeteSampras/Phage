// Package control is the thin request/response protocol between the phaged
// daemon and the phage CLI over a Unix socket. One JSON request, one JSON
// response, one connection — deliberately boring so the CLI stays a thin client
// and the daemon keeps all state.
package control

// Request is a single command from the CLI.
type Request struct {
	Cmd string `json:"cmd"`           // status | events | thaw
	PID int32  `json:"pid,omitempty"` // for thaw
	N   int    `json:"n,omitempty"`   // for events (how many)
}

// Status is a snapshot of the running daemon.
type Status struct {
	Mode      string `json:"mode"`
	Uptime    string `json:"uptime"`
	Events    uint64 `json:"events"`
	Alerts    uint64 `json:"alerts"`
	Contained uint64 `json:"contained"`

	// Sensor health (zero/empty from an older daemon).
	Unlearned      uint64  `json:"unlearned,omitempty"`       // events whose feature class has no baseline
	Drops          *uint64 `json:"drops,omitempty"`           // ring-buffer drops since the sensors loaded; absent when unknown
	DropsError     string  `json:"drops_error,omitempty"`     // why Drops could not be read
	EventsPerSec   float64 `json:"events_per_sec"`            // over the last heartbeat interval
	EnrichLagMs    float64 `json:"enrich_lag_ms"`             // average, over the last heartbeat interval
	LastHeartbeat  string  `json:"last_heartbeat,omitempty"`  // RFC 3339
	BaselineSHA256 string  `json:"baseline_sha256,omitempty"` // the baseline in use ("none": fresh host)
	BaselineState  string  `json:"baseline_state,omitempty"`  // no_baseline | warming | ready
	Overflow       uint64  `json:"baseline_overflow"`         // values refused at learn.max_values_per_key
	NoveltyPath    string  `json:"novelty_path,omitempty"`
	NoveltyRows    uint64  `json:"novelty_rows"`
	NoveltyErrors  uint64  `json:"novelty_errors"`
}

// Alert is one surfaced verdict, as kept in the daemon's recent-alerts ring.
// Requested/Action/Outcome match the audit trail's response record.
type Alert struct {
	Time      string  `json:"time"`
	Score     float64 `json:"score"`
	Requested string  `json:"requested,omitempty"` // the rung the response matrix chose
	Action    string  `json:"action"`              // the rung actually applied
	Outcome   string  `json:"outcome,omitempty"`   // contained | notified | skipped:<why> | failed:<err>
	PID       int32   `json:"pid"`
	Comm      string  `json:"comm"`
	Reason    string  `json:"reason"`
}

// Response is the daemon's reply.
type Response struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Status  *Status `json:"status,omitempty"`
	Alerts  []Alert `json:"alerts,omitempty"`
	Message string  `json:"message,omitempty"`
}
