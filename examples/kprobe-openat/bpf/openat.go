//go:build tinygo

package main

import "unsafe"

const (
	bpfMapTypeRingbuf = 27
	commLen           = 16
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
	UID      uint32
	Flags    uint32
	_        uint32
	Comm     [commLen]byte
	Filename [64]byte
}

type ptRegs struct {
	_        [8]byte  // x0: dfd
	Filename uint64   // x1: filename pointer
	Flags    uint64   // x2: flags
	_        [168]byte
}

//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

//go:extern bpf_get_current_uid_gid
func bpfGetCurrentUidGid() uint64

//go:extern bpf_get_current_comm
func bpfGetCurrentComm(buf unsafe.Pointer, size uint32) int64

//go:extern bpf_probe_read_user_str
func bpfProbeReadUserStr(dst unsafe.Pointer, size uint32, src unsafe.Pointer) int64

//go:extern bpf_ringbuf_output
func bpfRingbufOutput(mapPtr unsafe.Pointer, data unsafe.Pointer, size uint64, flags uint64) int64

// kprobe_openat traces file open operations and emits events to a ring buffer.
//
//export kprobe_openat
func kprobe_openat(ctx unsafe.Pointer) int32 {
	regs := (*ptRegs)(ctx)
	if regs == nil {
		return 0
	}

	var ev openEvent
	ev.PID = uint32(bpfGetCurrentPidTgid() >> 32)
	ev.UID = uint32(bpfGetCurrentUidGid())
	ev.Flags = uint32(regs.Flags)

	bpfGetCurrentComm(unsafe.Pointer(&ev.Comm), commLen)
	if regs.Filename != 0 {
		bpfProbeReadUserStr(unsafe.Pointer(&ev.Filename), 64, unsafe.Pointer(uintptr(regs.Filename)))
	}

	_ = bpfRingbufOutput(unsafe.Pointer(&events), unsafe.Pointer(&ev), uint64(unsafe.Sizeof(ev)), 0)
	return 0
}

func main() {}
