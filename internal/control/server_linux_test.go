//go:build linux

package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type fakeHandler struct{ thawed []int32 }

func (f *fakeHandler) Status() Status           { return Status{Mode: "alert"} }
func (f *fakeHandler) RecentAlerts(int) []Alert { return nil }
func (f *fakeHandler) Thaw(pid int32) error     { f.thawed = append(f.thawed, pid); return nil }

func startServer(t *testing.T, uid uint32) (string, *fakeHandler) {
	t.Helper()
	prev := allowedUID
	allowedUID = uid
	t.Cleanup(func() { allowedUID = prev })

	dir, err := os.MkdirTemp("", "phagectl") // short path: sun_path is 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "phage.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := &fakeHandler{}
	srv, err := Serve(ctx, path, h)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return path, h
}

func TestSocketIsOwnerOnly(t *testing.T) {
	path, _ := startServer(t, uint32(os.Getuid()))
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("socket mode = %v, want no group/other bits", perm)
	}
}

func TestPeerWithAllowedUIDIsServed(t *testing.T) {
	path, _ := startServer(t, uint32(os.Getuid()))
	resp, err := Do(path, Request{Cmd: "status"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Status == nil || resp.Status.Mode != "alert" {
		t.Fatalf("status from an allowed peer = %+v", resp)
	}
}

func TestPeerWithOtherUIDIsRejected(t *testing.T) {
	// Model an unprivileged caller by allowing a uid the test does not run as.
	path, h := startServer(t, uint32(os.Getuid())+12345)
	resp, err := Do(path, Request{Cmd: "thaw", PID: 42})
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Error != "permission denied" {
		t.Fatalf("response to a disallowed peer = %+v, want permission denied", resp)
	}
	if len(h.thawed) != 0 {
		t.Fatalf("handler ran for a disallowed peer: thawed %v", h.thawed)
	}
}
