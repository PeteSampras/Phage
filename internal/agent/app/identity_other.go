//go:build !linux

package app

import "errors"

// RootFileID needs openat2; off Linux the writer's view is unknown, so the
// heal gate falls back to the host file's own content.
func (hostProc) RootFileID(int32, string) (fileID, error) {
	return fileID{}, errors.New("unsupported on this platform")
}
