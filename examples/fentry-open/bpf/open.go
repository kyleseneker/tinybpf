// Compiled by TinyGo; see open_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const (
	bpfMapTypeRingbuf = 27
)

type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

var events = bpfMapDef{
	Type:       bpfMapTypeRingbuf,
	MaxEntries: 1 << 24,
}

type openEvent struct {
	PID      uint32
	Filename [64]byte
}

//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

//go:extern bpf_probe_read_kernel_str
func bpfProbeReadKernelStr(dst unsafe.Pointer, size uint32, src unsafe.Pointer) int64

//go:extern bpf_ringbuf_output
func bpfRingbufOutput(mapPtr unsafe.Pointer, data unsafe.Pointer, size uint64, flags uint64) int64

//go:extern bpf_get_current_task
func bpfGetCurrentTask() unsafe.Pointer

// trace_openat2 is the fentry entry point. //export keeps TinyGo from
// eliminating it; tinybpf assigns the fentry ELF section.
//
//export trace_openat2
func trace_openat2(ctx unsafe.Pointer) int32 {
	task := bpfGetCurrentTask()
	if task == nil {
		return 0
	}

	fnamePtr := *(*uint64)(unsafe.Pointer(uintptr(ctx) + 8))
	if fnamePtr == 0 {
		return 0
	}

	pid := uint32(bpfGetCurrentPidTgid() >> 32)

	var ev openEvent
	ev.PID = pid
	_ = bpfProbeReadKernelStr(unsafe.Pointer(&ev.Filename), 64, unsafe.Pointer(uintptr(fnamePtr)))

	_ = bpfRingbufOutput(unsafe.Pointer(&events), unsafe.Pointer(&ev), uint64(unsafe.Sizeof(ev)), 0)
	return 0
}

func main() {}
