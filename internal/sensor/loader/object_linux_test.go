//go:build linux

package loader

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// sensorsObject is the compiled sensor object (make bpf). These tests read the
// ELF only; nothing is loaded into the kernel.
func sensorsObject(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	p := filepath.Join("..", "..", "..", "bpf", "build", "sensors.bpf.o")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s not built (run make gen-vmlinux bpf)", p)
	}
	spec, err := ebpf.LoadCollectionSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestObjectHasThePerCPUDropCounter(t *testing.T) {
	m := sensorsObject(t).Maps[DropsMap]
	if m == nil {
		t.Fatalf("map %s missing", DropsMap)
	}
	if m.Type != ebpf.PerCPUArray || m.KeySize != 4 || m.ValueSize != 8 || m.MaxEntries != 1 {
		t.Errorf("%s = %v key %d value %d entries %d; want a 1-entry per-CPU array of u64", DropsMap, m.Type, m.KeySize, m.ValueSize, m.MaxEntries)
	}
}

// Every program that writes the ring buffer must also be able to count a
// failed reservation: a program referencing phage_events without phage_drops
// would drop silently.
func TestEveryRingBufferWriterCountsDrops(t *testing.T) {
	spec := sensorsObject(t)
	writers := 0
	for name, p := range spec.Programs {
		refs := map[string]bool{}
		for _, ins := range p.Instructions {
			if ins.IsLoadFromMap() || ins.OpCode.Class() == asm.LdClass {
				if r := ins.Reference(); r != "" {
					refs[r] = true
				}
			}
		}
		if !refs[mapName] {
			continue
		}
		writers++
		if !refs[DropsMap] {
			t.Errorf("program %s writes %s but never touches %s", name, mapName, DropsMap)
		}
	}
	if writers < 9 {
		t.Errorf("found %d ring-buffer writers, want every sensor (9 or more)", writers)
	}
}

// Reading a real per-CPU map goes through the same path as the daemon. Map
// creation needs CAP_BPF; where it is refused the test says so and skips.
func TestReadDropsFromARealPerCPUMap(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("cannot create a BPF map here: %v", err)
		}
		t.Fatal(err)
	}
	defer m.Close()
	n := ebpf.MustPossibleCPU()
	vals := make([]uint64, n)
	for i := range vals {
		vals[i] = uint64(i + 1)
	}
	if err := m.Put(uint32(0), vals); err != nil {
		t.Fatal(err)
	}
	got, err := readDrops(m)
	if want := uint64(n * (n + 1) / 2); err != nil || got != want {
		t.Fatalf("readDrops = %d, %v; want %d", got, err, want)
	}
}
