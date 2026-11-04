// Package honeytoken plants decoy credential files and reports their inodes so
// the kernel sensor can turn any *read* of one into a high-confidence alert.
// Nothing legitimate references these files, so a read means something is
// snooping for secrets. Decoys are created only where no real file exists — a
// honeytoken never clobbers a real credential — and are removed on shutdown.
//
// What was planted (each decoy's dev+ino and every directory created for it) is
// recorded in a state file, so that after a crash the next start re-adopts its
// own stale decoys instead of mistaking them for real files, and removal only
// ever deletes the exact inodes it created.
package honeytoken

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

// Decoy is one planted tripwire: a plausible path an intruder greps for, with
// obviously-inert fake content.
type Decoy struct {
	Path, Content string
}

// Decoys is the default set: credential-shaped bait in the places attackers look.
var Decoys = []Decoy{
	{"/root/.aws/credentials", "[default]\naws_access_key_id = AKIAEXAMPLEHONEYTOKEN\naws_secret_access_key = phage-decoy-not-a-real-key\n"},
	{"/root/.ssh/id_ed25519_backup", "-----BEGIN OPENSSH PRIVATE KEY-----\nphage-decoy-not-a-real-key-do-not-use\n-----END OPENSSH PRIVATE KEY-----\n"},
	{"/var/backups/.pgpass", "db.internal:5432:production:admin:phage-decoy-not-a-real-password\n"},
}

// Node identifies a file or directory the agent created.
type Node struct {
	Path string `json:"path"`
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
}

// Planted is one live decoy and the directories created to hold it (outermost
// first).
type Planted struct {
	Node
	SHA256  string `json:"sha256"` // of the decoy content: dev+ino alone can be reused
	Dirs    []Node `json:"dirs,omitempty"`
	Adopted bool   `json:"-"` // re-adopted from a previous run rather than created now
}

// Manager plants and removes decoys, keeping a record in statePath.
type Manager struct {
	statePath string
	decoys    []Decoy
}

// New returns a Manager for decoys, recording what it plants in statePath.
func New(statePath string, decoys []Decoy) *Manager {
	return &Manager{statePath: statePath, decoys: decoys}
}

// Seed plants every decoy whose path is free, re-adopts decoys a previous run
// planted (recorded dev+ino and exact content, or — with no record — exact
// content owned by root with mode 0600), and leaves anything else alone. It
// records the result in the state file and returns the live decoys.
func (m *Manager) Seed() ([]Planted, error) {
	prev := m.load()
	var out []Planted
	for _, d := range m.decoys {
		p, err := m.seedOne(d, prev[d.Path])
		if err != nil {
			log.Printf("honeytoken %q: %v", d.Path, err)
			continue
		}
		if p != nil {
			out = append(out, *p)
		}
		delete(prev, d.Path)
	}
	// Records for decoys no longer in the set: clean them up the safe way.
	for _, p := range prev {
		removeOne(*p)
	}
	if err := m.save(out); err != nil {
		// Without a record a crash would orphan the decoys; take them back down.
		Remove(out)
		return nil, fmt.Errorf("record planted decoys: %w", err)
	}
	return out, nil
}

func (m *Manager) seedOne(d Decoy, rec *Planted) (*Planted, error) {
	fi, err := os.Lstat(d.Path)
	if err == nil {
		if ours(d, fi, rec) {
			p := Planted{Node: nodeOf(d.Path, fi), SHA256: sum(d.Content), Adopted: true}
			if rec != nil && rec.Dev == p.Dev && rec.Ino == p.Ino {
				p.Dirs = rec.Dirs
			}
			return &p, nil
		}
		return nil, nil // a real file (or a link) lives here; never touch it
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dirs, err := mkdirs(filepath.Dir(d.Path))
	if err != nil {
		return nil, err
	}
	// O_EXCL|O_NOFOLLOW: create only a brand-new file, never write through a
	// symlink or into a file that appeared since the Lstat above.
	f, err := os.OpenFile(d.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		rmdirs(dirs)
		return nil, err
	}
	_, werr := f.WriteString(d.Content)
	st, serr := f.Stat()
	f.Close()
	if werr != nil || serr != nil {
		os.Remove(d.Path)
		rmdirs(dirs)
		return nil, errors.Join(werr, serr)
	}
	return &Planted{Node: nodeOf(d.Path, st), SHA256: sum(d.Content), Dirs: dirs}, nil
}

// ours decides whether an existing file at a decoy path is a decoy this agent
// planted earlier (re-adopt) rather than a real file (leave alone).
func ours(d Decoy, fi os.FileInfo, rec *Planted) bool {
	if !fi.Mode().IsRegular() {
		return false
	}
	b, err := os.ReadFile(d.Path)
	if err != nil || string(b) != d.Content {
		return false
	}
	n := nodeOf(d.Path, fi)
	if rec != nil && rec.Dev == n.Dev && rec.Ino == n.Ino {
		return true
	}
	// No record (e.g. the state file was lost): our exact content, root-owned,
	// 0600 — only root could have put it there, and only we use this content.
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && fi.Mode().Perm() == 0o600
}

func nodeOf(path string, fi os.FileInfo) Node {
	n := Node{Path: path}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		n.Dev, n.Ino = uint64(st.Dev), uint64(st.Ino)
	}
	return n
}

// mkdirs creates dir and any missing parents (0700), returning the ones it
// created, outermost first.
func mkdirs(dir string) ([]Node, error) {
	var missing []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		}
		missing = append([]string{d}, missing...)
		if d == filepath.Dir(d) {
			break
		}
	}
	var made []Node
	for _, d := range missing {
		if err := os.Mkdir(d, 0o700); err != nil {
			rmdirs(made)
			return nil, err
		}
		fi, err := os.Lstat(d)
		if err != nil {
			rmdirs(made)
			return nil, err
		}
		made = append(made, nodeOf(d, fi))
	}
	return made, nil
}

// rmdirs removes directories the agent created, innermost first, only if they
// are still the same inode and empty.
func rmdirs(dirs []Node) {
	for i := len(dirs) - 1; i >= 0; i-- {
		if same(dirs[i]) {
			if err := syscall.Rmdir(dirs[i].Path); err != nil && !errors.Is(err, syscall.ENOTEMPTY) {
				log.Printf("honeytoken: remove created dir %q: %v", dirs[i].Path, err)
			}
		}
	}
}

func same(n Node) bool {
	fi, err := os.Lstat(n.Path)
	if err != nil {
		return false
	}
	got := nodeOf(n.Path, fi)
	return got.Dev == n.Dev && got.Ino == n.Ino
}

func sum(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// stillOurs: the path is the planted inode AND still holds the decoy content
// (an inode number freed by a delete can be reused by someone else's file).
func stillOurs(p Planted) bool {
	if !same(p.Node) {
		return false
	}
	b, err := os.ReadFile(p.Path)
	return err == nil && sum(string(b)) == p.SHA256
}

func removeOne(p Planted) {
	if stillOurs(p) {
		if err := os.Remove(p.Path); err != nil {
			log.Printf("honeytoken: remove %q: %v", p.Path, err)
		}
	} else if _, err := os.Lstat(p.Path); err == nil {
		log.Printf("honeytoken: %q is no longer the decoy that was planted; leaving it", p.Path)
	}
	rmdirs(p.Dirs)
}

// Remove deletes decoys previously planted — each only if the path is still
// the exact inode that was planted — and the directories created for them.
func Remove(planted []Planted) {
	for _, p := range planted {
		removeOne(p)
	}
}

// Shutdown removes the decoys and their record.
func (m *Manager) Shutdown(planted []Planted) {
	Remove(planted)
	if err := os.Remove(m.statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("honeytoken: remove state %q: %v", m.statePath, err)
	}
}

// Inodes returns the inode numbers to register with the kernel sensor.
func Inodes(planted []Planted) []uint64 {
	out := make([]uint64, 0, len(planted))
	for _, p := range planted {
		out = append(out, p.Ino)
	}
	return out
}

func (m *Manager) load() map[string]*Planted {
	out := map[string]*Planted{}
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		return out
	}
	var recs []Planted
	if err := json.Unmarshal(b, &recs); err != nil {
		log.Printf("honeytoken: ignoring unreadable state %q: %v", m.statePath, err)
		return out
	}
	for i := range recs {
		out[recs[i].Path] = &recs[i]
	}
	return out
}

// save writes the record atomically (temp file in the same directory, 0600,
// then rename).
func (m *Manager) save(planted []Planted) error {
	b, err := json.Marshal(planted)
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.statePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".honeytokens-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if err := os.Rename(tmp, m.statePath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
