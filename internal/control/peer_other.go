//go:build !linux

package control

import (
	"errors"
	"net"
	"os"
)

func listenPrivate(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return ln, nil
}

// checkPeer fails closed off Linux: peer-credential checks are implemented for
// Linux only, which is the only platform the daemon runs on.
func checkPeer(net.Conn) error {
	return errors.New("peer credential check unsupported on this platform")
}
