package loader

import (
	"errors"
	"testing"
)

type fakePerCPU struct {
	slots []uint64
	err   error
	key   interface{}
}

func (f *fakePerCPU) Lookup(key, out interface{}) error {
	f.key = key
	if f.err != nil {
		return f.err
	}
	*(out.(*[]uint64)) = append([]uint64(nil), f.slots...)
	return nil
}

func TestReadDropsSumsEveryCPU(t *testing.T) {
	f := &fakePerCPU{slots: []uint64{3, 0, 7, 1 << 40}}
	n, err := readDrops(f)
	if err != nil || n != 10+1<<40 {
		t.Fatalf("readDrops = %d, %v", n, err)
	}
	if k, ok := f.key.(uint32); !ok || k != 0 {
		t.Errorf("looked up key %#v, want uint32(0) (the map's only entry)", f.key)
	}
}

func TestReadDropsPropagatesErrors(t *testing.T) {
	want := errors.New("EPERM")
	if _, err := readDrops(&fakePerCPU{err: want}); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}
