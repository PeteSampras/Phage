// Package honeytoken plants decoy credential files and reports their inodes so
// the kernel sensor can turn any *read* of one into a high-confidence alert.
// Nothing legitimate references these files, so a read means something is
// snooping for secrets. Decoys are created only where no real file exists — a
// honeytoken never clobbers a real credential — and are removed on shutdown.
package honeytoken

import (
	"os"
	"path/filepath"
	"syscall"
)

// decoy is one planted tripwire: a plausible path an intruder greps for, with
// obviously-inert fake content.
type decoy struct {
	path, content string
}

// Decoys is the default set: credential-shaped bait in the places attackers look.
var Decoys = []decoy{
	{"/root/.aws/credentials", "[default]\naws_access_key_id = AKIAEXAMPLEHONEYTOKEN\naws_secret_access_key = phage-decoy-not-a-real-key\n"},
	{"/root/.ssh/id_ed25519_backup", "-----BEGIN OPENSSH PRIVATE KEY-----\nphage-decoy-not-a-real-key-do-not-use\n-----END OPENSSH PRIVATE KEY-----\n"},
	{"/var/backups/.pgpass", "db.internal:5432:production:admin:phage-decoy-not-a-real-password\n"},
}

// Seed creates the decoys that do not already exist and returns the paths it
// created together with their inode numbers (for the kernel sensor). Existing
// files are left untouched and not treated as decoys.
func Seed() (paths []string, inodes []uint64) {
	for _, d := range Decoys {
		if _, err := os.Lstat(d.path); err == nil {
			continue // a real file (or a link) lives here; never overwrite it
		}
		if err := os.MkdirAll(filepath.Dir(d.path), 0o700); err != nil {
			continue
		}
		// O_EXCL|O_NOFOLLOW: create only a brand-new file, never write through a
		// symlink or into a file that appeared since the Lstat above.
		f, err := os.OpenFile(d.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			continue
		}
		_, werr := f.WriteString(d.content)
		var st syscall.Stat_t
		serr := syscall.Fstat(int(f.Fd()), &st)
		f.Close()
		if werr != nil || serr != nil {
			os.Remove(d.path)
			continue
		}
		paths = append(paths, d.path)
		inodes = append(inodes, uint64(st.Ino))
	}
	return paths, inodes
}

// Remove deletes decoys previously created by Seed.
func Remove(paths []string) {
	for _, p := range paths {
		os.Remove(p)
	}
}
