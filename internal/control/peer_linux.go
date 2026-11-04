//go:build linux

package control

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// allowedUID is the only peer uid the control socket serves. Tests override it.
var allowedUID uint32 = 0

// umaskMu serialises the process-wide umask change in listenPrivate.
var umaskMu sync.Mutex

// listenPrivate binds the Unix socket with umask 077 so the socket inode is
// created 0600 (srw-------) rather than 0777-and-chmod-later. umask is
// process-wide; the daemon calls this once at startup before it serves files.
func listenPrivate(path string) (net.Listener, error) {
	umaskMu.Lock()
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	umaskMu.Unlock()
	return ln, err
}

// checkPeer reads the connecting process's credentials from the kernel
// (SO_PEERCRED — not something the client can claim) and admits only
// allowedUID (root).
func checkPeer(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	if cred.Uid != allowedUID {
		return fmt.Errorf("peer pid %d uid %d is not uid %d", cred.Pid, cred.Uid, allowedUID)
	}
	return nil
}
