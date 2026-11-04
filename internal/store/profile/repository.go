// Package profile defines how a learned baseline is persisted. The interface is
// deliberately tiny — load the baseline at startup, save it when learning — so
// the backend (a JSON snapshot today, an embedded KV later) can change without
// touching the agent.
package profile

import "github.com/AzozzALFiras/Phage/internal/analysis/baseline"

// Repository loads and saves a baseline Profile.
type Repository interface {
	// Load fills p from storage. A missing store is not an error: p is left
	// empty so a fresh host simply starts learning from nothing.
	Load(p *baseline.Profile) error
	// Save persists p's current learned state.
	Save(p *baseline.Profile) error
	// Digest identifies the stored baseline as last loaded or saved (the hex
	// sha256 of its bytes), or "none" when nothing is stored yet.
	Digest() string
}
