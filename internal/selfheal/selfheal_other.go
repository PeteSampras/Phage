//go:build !linux

package selfheal

import "errors"

// errUnsupported: the symlink-safe primitives self-heal relies on (openat2,
// O_NOFOLLOW walks, fd-relative renames) are implemented for Linux only, which
// is the only platform the agent runs its sensors on.
var errUnsupported = errors.New("self-heal is supported on Linux only")

func prepareQuarantine(string) error                       { return errUnsupported }
func readSnapshot(string) (snapshot, error)                { return snapshot{}, errUnsupported }
func heal(string, snapshot, string, int64) (string, error) { return "", errUnsupported }
