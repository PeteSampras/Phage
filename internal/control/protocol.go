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
