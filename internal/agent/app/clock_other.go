//go:build !linux

package app

// monotonicNow is unavailable off Linux (there are no kernel events to time).
func monotonicNow() (uint64, bool) { return 0, false }
