//go:build !linux

// This stub lets the whole module build and unit-test on non-Linux machines
// (e.g. a macOS dev laptop). The eBPF sensors themselves only exist on Linux;
// here every entry point fails cleanly instead of failing to compile.
package loader

import "errors"

// ErrUnsupported is returned by all loader operations off Linux.
var ErrUnsupported = errors.New("phage: eBPF sensors are only supported on Linux")

// Sensor is a no-op placeholder on non-Linux platforms.
type Sensor struct{}

// Load always fails off Linux.
func Load(objPath string) (*Sensor, error) { return nil, ErrUnsupported }

// Read always fails off Linux.
func (s *Sensor) Read() ([]byte, error) { return nil, ErrUnsupported }

// SetSelfPID is a no-op off Linux.
func (s *Sensor) SetSelfPID(pid uint32) error { return nil }

// SetHoneytokens is a no-op off Linux.
func (s *Sensor) SetHoneytokens(inodes []uint64) error { return nil }

// Drops always fails off Linux.
func (s *Sensor) Drops() (uint64, error) { return 0, ErrUnsupported }

// Close is a no-op off Linux.
func (s *Sensor) Close() error { return nil }
