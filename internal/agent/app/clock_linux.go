//go:build linux

package app

import "golang.org/x/sys/unix"

// monotonicNow reads CLOCK_MONOTONIC, the clock bpf_ktime_get_ns uses for the
// sensors' event timestamps.
func monotonicNow() (uint64, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, false
	}
	return uint64(ts.Nano()), true
}
