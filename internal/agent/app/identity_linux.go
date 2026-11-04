//go:build linux

package app

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// RootFileID resolves path inside the process's root directory with
// openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS) and stats
// what it names, without opening it for reading.
func (hostProc) RootFileID(pid int32, path string) (fileID, error) {
	root, err := unix.Open(fmt.Sprintf("/proc/%d/root", pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fileID{}, err
	}
	defer unix.Close(root)
	fd, err := unix.Openat2(root, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fileID{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileID{}, err
	}
	return fileID{uint64(st.Dev), st.Ino}, nil
}
