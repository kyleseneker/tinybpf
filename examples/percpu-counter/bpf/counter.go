// Compiled by TinyGo; see counter_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const (
	bpfMapTypePercpuArray = 6
)

type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// counters is a per-CPU array map. Each CPU maintains its own copy of
// every entry, eliminating lock contention on the hot path.
var counters = bpfMapDef{
	Type:       bpfMapTypePercpuArray,
	KeySize:    4,
	ValueSize:  8,
	MaxEntries: 1,
}

//go:extern bpf_map_lookup_elem
func bpfMapLookupElem(mapPtr unsafe.Pointer, key unsafe.Pointer) unsafe.Pointer

// tracepoint_syscalls_sys_enter increments a per-CPU counter on every syscall entry.
//
//export tracepoint_syscalls_sys_enter
func tracepoint_syscalls_sys_enter(ctx unsafe.Pointer) int32 { //nolint:revive
	var key uint32
	valPtr := bpfMapLookupElem(unsafe.Pointer(&counters), unsafe.Pointer(&key))
	if valPtr != nil {
		val := (*uint64)(valPtr)
		*val++
	}
	return 0
}

func main() {}
