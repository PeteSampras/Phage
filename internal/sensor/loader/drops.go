package loader

import "errors"

// DropsMap is the per-CPU counter in bpf/programs/sensors.bpf.c that every
// sensor increments when bpf_ringbuf_reserve fails: an event the kernel saw
// and phaged never received.
const DropsMap = "phage_drops"

// ErrNoDropCounter means the loaded object has no drop counter (an object
// built before the counter existed). The daemon reports it rather than a 0.
var ErrNoDropCounter = errors.New("sensor object has no " + DropsMap + " map (rebuild the eBPF objects)")

// perCPULookup is the one map operation the drop count needs. *ebpf.Map
// satisfies it; tests use a fake, because loading a map needs privileges.
type perCPULookup interface {
	Lookup(key, valueOut interface{}) error
}

// readDrops sums the per-CPU slots of the drop counter's single entry.
func readDrops(m perCPULookup) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var sum uint64
	for _, n := range perCPU {
		sum += n
	}
	return sum, nil
}
