// Compiled by TinyGo; see sched_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const (
	bpfMapTypePerfEventArray = 4
)

type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// events is a perf event array for sending exec events to userspace.
var events = bpfMapDef{
	Type:       bpfMapTypePerfEventArray,
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: 128,
}

// bpfCoreTaskStruct is a CO-RE portable kernel struct stub.
// Field offsets are resolved at load time via BTF relocations,
// so this program works across kernel versions even if the
// layout of task_struct changes.
type bpfCoreTaskStruct struct {
	Pid  int32
	Tgid int32
}

// Anchor the struct type in LLVM IR so the CO-RE transform can
// discover its layout. TinyGo strips named types that are only
// used in local variables; a package-level extern forces emission.
//
//go:extern __bpf_core_task_struct
var _coreTaskStruct bpfCoreTaskStruct

type execEvent struct {
	Pid  uint32
	Tgid uint32
	Comm [16]byte
}

//go:extern bpf_get_current_task
func bpfGetCurrentTask() unsafe.Pointer

//go:extern bpf_probe_read_kernel
func bpfProbeReadKernel(dst unsafe.Pointer, size uint32, src unsafe.Pointer) int64

//go:extern bpf_get_current_comm
func bpfGetCurrentComm(buf unsafe.Pointer, size uint32) int32

//go:extern bpf_perf_event_output
func bpfPerfEventOutput(ctx unsafe.Pointer, mapPtr unsafe.Pointer, flags uint64, data unsafe.Pointer, size uint32) int64

//go:extern bpf_core_field_exists
func bpfCoreFieldExists(field unsafe.Pointer) int32

// raw_tracepoint_sched_process_exec fires on every execve.
// It reads pid/tgid from the current task using CO-RE portable
// field access. Uses bpfCoreFieldExists to conditionally read
// tgid only when the kernel's task_struct contains it.
//
//export raw_tracepoint_sched_process_exec
func raw_tracepoint_sched_process_exec(ctx unsafe.Pointer) int32 { //nolint:revive
	task := bpfGetCurrentTask()
	if task == nil {
		return 0
	}

	var core bpfCoreTaskStruct
	bpfProbeReadKernel(unsafe.Pointer(&core), uint32(unsafe.Sizeof(core)), task)

	var ev execEvent
	ev.Pid = uint32(core.Pid)
	if bpfCoreFieldExists(unsafe.Pointer(&core.Tgid)) != 0 {
		ev.Tgid = uint32(core.Tgid)
	}
	bpfGetCurrentComm(unsafe.Pointer(&ev.Comm), 16)

	bpfPerfEventOutput(ctx, unsafe.Pointer(&events), 0xFFFFFFFF, unsafe.Pointer(&ev), uint32(unsafe.Sizeof(ev)))

	return 0
}

func main() {}
