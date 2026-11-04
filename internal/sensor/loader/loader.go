//go:build linux

// Package loader is the userspace side of the eBPF sensors: it loads the
// compiled CO-RE object, attaches the programs, and exposes the ring buffer as
// a stream of raw event samples. Decoding and enrichment happen downstream so
// this package stays a thin, replaceable bridge to the kernel.
package loader

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// mapName is the shared ring buffer in bpf/programs/sensors.bpf.c. Every program
// in the object (commit_creds, sched_exec, tcp_connect, security_file_open) is a
// tracing program and is attached.
const mapName = "phage_events"

// Sensor is a loaded, attached set of eBPF programs plus their shared ring buffer.
type Sensor struct {
	coll      *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
	closeOnce sync.Once
}

// Load reads the compiled object at objPath, loads it into the kernel, attaches
// every tracing program it contains, and opens the shared ring buffer.
func Load(objPath string) (*Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec %q: %w", objPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load into kernel: %w", err)
	}

	s := &Sensor{coll: coll}
	for name, prog := range coll.Programs {
		lnk, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %q: %w", name, err)
		}
		s.links = append(s.links, lnk)
	}
	if len(s.links) == 0 {
		s.Close()
		return nil, fmt.Errorf("no programs found in %q", objPath)
	}

	m := coll.Maps[mapName]
	if m == nil {
		s.Close()
		return nil, fmt.Errorf("ring buffer map %q not found", mapName)
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	s.reader = rd
	return s, nil
}

// SetSelfPID tells the kernel sensors the agent's own tgid, arming the
// self-defense programs (they ignore signals/ptrace unless the target is the
// agent). A missing map is not fatal — self-defense is simply inert.
func (s *Sensor) SetSelfPID(pid uint32) error {
	m := s.coll.Maps["self_pid"]
	if m == nil {
		return nil
	}
	return m.Update(uint32(0), pid, ebpf.UpdateAny)
}

// SetHoneytokens registers decoy inode numbers and arms the honeytoken tripwire.
// An empty list disarms it. A missing map is not fatal.
func (s *Sensor) SetHoneytokens(inodes []uint64) error {
	ht := s.coll.Maps["honeytokens"]
	armed := s.coll.Maps["ht_armed"]
	if ht == nil || armed == nil {
		return nil
	}
	for _, ino := range inodes {
		if err := ht.Update(ino, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("register honeytoken %d: %w", ino, err)
		}
	}
	on := uint32(0)
	if len(inodes) > 0 {
		on = 1
	}
	return armed.Update(uint32(0), on, ebpf.UpdateAny)
}

// Drops returns the number of events the sensors failed to queue (a full ring
// buffer) since they were loaded, summed over every CPU.
func (s *Sensor) Drops() (uint64, error) {
	m := s.coll.Maps[DropsMap]
	if m == nil {
		return 0, ErrNoDropCounter
	}
	return readDrops(m)
}

// Read returns the next raw event sample. It blocks until a sample arrives or
// the Sensor is closed, in which case it returns ringbuf.ErrClosed.
func (s *Sensor) Read() ([]byte, error) {
	rec, err := s.reader.Read()
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

// Close detaches the programs and releases all kernel resources. Closing the
// reader unblocks any in-flight Read, which then returns ringbuf.ErrClosed — the
// reader is NOT nilled, so a concurrent Read never dereferences nil. Idempotent:
// the ctx-cancel goroutine and the deferred Close may both call it.
func (s *Sensor) Close() error {
	s.closeOnce.Do(func() {
		if s.reader != nil {
			s.reader.Close()
		}
		for _, lnk := range s.links {
			lnk.Close()
		}
		if s.coll != nil {
			s.coll.Close()
		}
	})
	return nil
}
