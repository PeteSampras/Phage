//go:build linux

// Package selfprotect is the eBPF-LSM tamper-resistance layer: it denies a
// lethal/stop signal aimed at the agent from an unauthorized sender, so an
// attacker cannot blind Phage by killing it. It is loaded only when the operator
// opts in (`mode: enforce` + `enforcement.self_protect: true`) and the kernel has BPF LSM active; everywhere else
// the agent runs without it rather than failing to start.
package selfprotect

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/AzozzALFiras/Phage/internal/jail/enforce"
)

const guardProg = "guard_task_kill"

// Available reports whether tamper-resistance can be armed on this kernel.
func Available() bool { return enforce.BPFLSMActive() }

// Guard is a loaded, attached self-protection LSM program.
type Guard struct {
	coll *ebpf.Collection
	link link.Link
}

// Arm loads the object, points it at the agent (pid + launcher ppid), and
// enables enforcement. pid 1 (systemd/init), the launcher, and the agent itself
// are always allowed to signal it, so `systemctl stop` and reboot always work.
func Arm(objPath string, pid, ppid uint32) (*Guard, error) {
	if !enforce.BPFLSMActive() {
		return nil, errors.New("BPF LSM not active; cannot arm self-protection")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load %q: %w", objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load into kernel: %w", err)
	}
	g := &Guard{coll: coll}

	for name, val := range map[string]uint32{"sp_self_pid": pid, "sp_self_ppid": ppid, "sp_protect": 1} {
		m := coll.Maps[name]
		if m == nil {
			g.Close()
			return nil, fmt.Errorf("map %q not found", name)
		}
		if err := m.Update(uint32(0), val, ebpf.UpdateAny); err != nil {
			g.Close()
			return nil, fmt.Errorf("set %q: %w", name, err)
		}
	}

	prog := coll.Programs[guardProg]
	if prog == nil {
		g.Close()
		return nil, fmt.Errorf("program %q not found", guardProg)
	}
	lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		g.Close()
		return nil, fmt.Errorf("attach LSM %q: %w", guardProg, err)
	}
	g.link = lnk
	return g, nil
}

// Close detaches the program (lifting all protection) and frees resources.
func (g *Guard) Close() error {
	if g.link != nil {
		g.link.Close()
		g.link = nil
	}
	if g.coll != nil {
		g.coll.Close()
		g.coll = nil
	}
	return nil
}
