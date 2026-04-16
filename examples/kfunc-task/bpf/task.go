// Compiled by TinyGo; see task_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const bpfMapTypeRingbuf = 27

type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// events is a ring buffer for sending task-lookup results to userspace.
var events = bpfMapDef{
	Type:       bpfMapTypeRingbuf,
	MaxEntries: 1 << 24,
}

type taskEvent struct {
	Pid   uint32
	Found uint32
}

// Helpers.

//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

//go:extern bpf_ringbuf_output
func bpfRingbufOutput(ringbuf unsafe.Pointer, data unsafe.Pointer, size uint64, flags uint64) int64

// kfuncs. The loader resolves these via kernel BTF at load time.
//
// bpf_task_from_pid returns a referenced task_struct pointer for the given
// PID, or NULL if no task is found. The verifier requires the returned
// reference to be released via bpf_task_release before the program exits.
// Available since kernel 6.1.

//go:extern bpf_task_from_pid
func bpfKfuncBpfTaskFromPid(pid int32) unsafe.Pointer

//go:extern bpf_task_release
func bpfKfuncBpfTaskRelease(task unsafe.Pointer)

// trace_openat2 fires on every file open, looks up the calling task via a
// kfunc, and emits the PID and lookup result to userspace.
//
//export trace_openat2
func trace_openat2(ctx unsafe.Pointer) int32 { //nolint:revive
	pid := int32(bpfGetCurrentPidTgid() >> 32)

	var ev taskEvent
	ev.Pid = uint32(pid)

	task := bpfKfuncBpfTaskFromPid(pid)
	if task != nil {
		ev.Found = 1
		bpfKfuncBpfTaskRelease(task)
	}

	_ = bpfRingbufOutput(unsafe.Pointer(&events), unsafe.Pointer(&ev), uint64(unsafe.Sizeof(ev)), 0)
	return 0
}

func main() {}
