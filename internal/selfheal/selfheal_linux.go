//go:build linux

package selfheal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// forceWalk makes openNoSymlinks skip openat2 and use the component walk, so
// tests can exercise the fallback used on kernels older than 5.6 (or where a
// seccomp filter hides openat2).
var forceWalk = false

// openNoSymlinks opens an absolute path without following a symlink in ANY
// component (including the last). It prefers openat2(RESOLVE_NO_SYMLINKS) and
// falls back to walking the path one component at a time with O_NOFOLLOW.
func openNoSymlinks(path string, flags int) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("%w: %q is not absolute", ErrUnsafe, path)
	}
	path = filepath.Clean(path)
	flags |= unix.O_NOFOLLOW | unix.O_CLOEXEC
	if !forceWalk {
		how := unix.OpenHow{
			Flags:   uint64(flags),
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		}
		fd, err := unix.Openat2(unix.AT_FDCWD, path, &how)
		if err != unix.ENOSYS && err != unix.EPERM {
			return fd, symlinkErr(path, err)
		}
	}
	return walkNoSymlinks(path, flags)
}

func walkNoSymlinks(path string, flags int) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	for i, comp := range parts {
		f := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i == len(parts)-1 {
			f = flags
		}
		nfd, err := unix.Openat(fd, comp, f, 0)
		unix.Close(fd)
		if err != nil {
			return -1, symlinkErr(path, err)
		}
		fd = nfd
	}
	if len(parts) == 0 {
		unix.Close(fd)
		return unix.Open("/", flags, 0)
	}
	return fd, nil
}

// symlinkErr turns the errno a no-follow open returns on a symlink into an
// ErrUnsafe refusal, leaving every other error as is.
func symlinkErr(path string, err error) error {
	if err == unix.ELOOP || err == unix.ENOTDIR || err == unix.EXDEV {
		return fmt.Errorf("%w: %q is or passes through a symlink: %v", ErrUnsafe, path, err)
	}
	return err
}

// prepareQuarantine creates (0700) and vets the quarantine/staging directory.
func prepareQuarantine(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("quarantine dir: %w", err)
	}
	fd, err := openNoSymlinks(dir, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("quarantine dir %q: %w", dir, err)
	}
	defer unix.Close(fd)
	return vetQuarantineFd(dir, fd)
}

func vetQuarantineFd(dir string, fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: quarantine %q is not a directory", ErrUnsafe, dir)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: quarantine %q is owned by uid %d, not the agent (uid %d)", ErrUnsafe, dir, st.Uid, os.Geteuid())
	}
	if st.Mode&0o077 != 0 {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			return fmt.Errorf("quarantine %q: tighten to 0700: %w", dir, err)
		}
	}
	return nil
}

// openParent opens the directory holding path, symlink-free, and returns it
// with its stat.
func openParent(path string) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := openNoSymlinks(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return -1, st, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, st, err
	}
	return fd, st, nil
}

// parentOwnerOK is the rule for a directory root may write into on someone's
// behalf: it must belong to root or to the owner of the file being healed.
// A directory owned by a third user is somewhere that user can stage a race.
func parentOwnerOK(dir unix.Stat_t, fileUID int) bool {
	return dir.Uid == 0 || int(dir.Uid) == fileUID
}

// openRegular opens base inside dirfd read-only without following a symlink and
// requires a regular file. Returns ENOENT unchanged so callers can tell a
// deleted file from an unsafe one.
func openRegular(dirfd int, path string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat(dirfd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return nil, st, err
		}
		return nil, st, symlinkErr(path, err)
	}
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, st, fmt.Errorf("%w: %q is not a regular file", ErrUnsafe, path)
	}
	return os.NewFile(uintptr(fd), path), st, nil
}

func readBounded(f *os.File) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, maxSnapshot+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshot {
		return nil, fmt.Errorf("%q larger than %d bytes; not a sentinel", f.Name(), maxSnapshot)
	}
	return data, nil
}

func readSnapshot(path string) (snapshot, error) {
	dirfd, dst, err := openParent(path)
	if err != nil {
		return snapshot{}, err
	}
	defer unix.Close(dirfd)
	f, st, err := openRegular(dirfd, path)
	if err != nil {
		return snapshot{}, err
	}
	defer f.Close()
	if !parentOwnerOK(dst, int(st.Uid)) {
		return snapshot{}, fmt.Errorf("%w: parent of %q is owned by uid %d (neither root nor the file owner uid %d)",
			ErrUnsafe, path, dst.Uid, st.Uid)
	}
	data, err := readBounded(f)
	if err != nil {
		return snapshot{}, err
	}
	return snapshot{
		content: data,
		mode:    os.FileMode(st.Mode & 0o777),
		uid:     int(st.Uid),
		gid:     int(st.Gid),
		dirDev:  uint64(dst.Dev),
		dirIno:  dst.Ino,
	}, nil
}

func heal(path string, snap snapshot, quarantine string) (string, error) {
	dirfd, dst, err := openParent(path)
	if err != nil {
		return "", fmt.Errorf("open parent: %w", err)
	}
	defer unix.Close(dirfd)
	if uint64(dst.Dev) != snap.dirDev || dst.Ino != snap.dirIno {
		return "", fmt.Errorf("%w: parent directory of %q was replaced since it was snapshotted", ErrUnsafe, path)
	}
	if !parentOwnerOK(dst, snap.uid) {
		return "", fmt.Errorf("%w: parent of %q is owned by uid %d (neither root nor the file owner uid %d)",
			ErrUnsafe, path, dst.Uid, snap.uid)
	}

	// Current (tampered) content. A deleted file is restored; a file swapped for
	// a symlink or anything non-regular is refused (we never act through it).
	var cur []byte
	if f, _, err := openRegular(dirfd, path); err == nil {
		cur, err = readBounded(f)
		f.Close()
		if err != nil {
			return "", err
		}
	} else if err != unix.ENOENT {
		return "", err
	}
	if bytes.Equal(cur, snap.content) {
		return "", nil // unchanged from known-good; the write was benign/identical
	}

	qfd, err := openNoSymlinks(quarantine, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return "", fmt.Errorf("quarantine dir: %w", err)
	}
	defer unix.Close(qfd)
	if err := vetQuarantineFd(quarantine, qfd); err != nil {
		return "", err
	}

	// Evidence first. Failing to keep it must not stop the restore.
	var qpath string
	if len(cur) > 0 {
		name := fmt.Sprintf("%d-%s", time.Now().Unix(), sanitize(path))
		if n, err := writeExcl(qfd, name, cur, os.Getuid(), os.Getgid(), 0o600); err != nil {
			log.Printf("self-heal %q: evidence not saved: %v", path, err)
		} else {
			qpath = filepath.Join(quarantine, n)
		}
	}

	// Stage the restored content in the root-only quarantine dir and rename it
	// into place. If the target lives on another filesystem (EXDEV), stage next
	// to it instead — still O_EXCL|O_NOFOLLOW under a random name, so a
	// pre-planted file or symlink can only make the create fail, never redirect it.
	base := filepath.Base(path)
	tmp, err := writeExcl(qfd, ".stage-"+base, snap.content, snap.uid, snap.gid, snap.mode)
	if err != nil {
		return qpath, fmt.Errorf("stage restored content: %w", err)
	}
	err = unix.Renameat(qfd, tmp, dirfd, base)
	if err == unix.EXDEV {
		unix.Unlinkat(qfd, tmp, 0)
		tmp, err = writeExcl(dirfd, ".phage-heal-"+base, snap.content, snap.uid, snap.gid, snap.mode)
		if err != nil {
			return qpath, fmt.Errorf("stage restored content: %w", err)
		}
		if err = unix.Renameat(dirfd, tmp, dirfd, base); err != nil {
			unix.Unlinkat(dirfd, tmp, 0)
		}
	} else if err != nil {
		unix.Unlinkat(qfd, tmp, 0)
	}
	if err != nil {
		return qpath, fmt.Errorf("atomic restore: %w", err)
	}
	return qpath, nil
}

// writeExcl creates a new file in dirfd (never an existing one, never through a
// symlink), sets owner then mode on the descriptor, writes data and fsyncs. It
// returns the name actually created (a random suffix is appended).
func writeExcl(dirfd int, prefix string, data []byte, uid, gid int, mode os.FileMode) (string, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	name := prefix + "." + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), name)
	fail := func(err error) (string, error) {
		f.Close()
		unix.Unlinkat(dirfd, name, 0)
		return "", err
	}
	// chown before chmod: chown clears set-id bits, and the final mode must win.
	if err := f.Chown(uid, gid); err != nil {
		return fail(fmt.Errorf("fchown: %w", err))
	}
	if err := f.Chmod(mode); err != nil {
		return fail(fmt.Errorf("fchmod: %w", err))
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		unix.Unlinkat(dirfd, name, 0)
		return "", err
	}
	return name, nil
}
