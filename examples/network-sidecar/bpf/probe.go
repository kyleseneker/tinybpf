// Compiled by TinyGo; see probe_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const (
	afINET            = 2
	ipProtoTCP        = 6
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

type connectEvent struct {
	PID       uint32
	DstAddrBE uint32
	DstPortBE uint16
	Proto     uint8
	_         uint8
	Comm      [4]byte
}

type tpConnectArgs struct {
	_         [24]byte
	Uservaddr uint64
}

type sockaddrIn struct {
	Family uint16
	PortBE uint16
	AddrBE uint32
	_      [8]byte
}

//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

//go:extern bpf_probe_read_user
func bpfProbeReadUser(dst unsafe.Pointer, size uint32, src unsafe.Pointer) int64

//go:extern bpf_ringbuf_output
func bpfRingbufOutput(mapPtr unsafe.Pointer, data unsafe.Pointer, size uint64, flags uint64) int64

// handle_connect is the tracepoint entry point. //export keeps TinyGo from
// eliminating it; tinybpf assigns the tracepoint ELF section.
//
//export handle_connect
func handle_connect(ctx unsafe.Pointer) int32 {
	args := (*tpConnectArgs)(ctx)
	if args == nil || args.Uservaddr == 0 {
		return 0
	}

	var sa sockaddrIn
	if bpfProbeReadUser(unsafe.Pointer(&sa), uint32(unsafe.Sizeof(sa)), unsafe.Pointer(uintptr(args.Uservaddr))) != 0 {
		return 0
	}
	if sa.Family != afINET {
		return 0
	}

	pid := uint32(bpfGetCurrentPidTgid() >> 32)
	ev := connectEvent{
		PID:       pid,
		DstAddrBE: sa.AddrBE,
		DstPortBE: sa.PortBE,
		Proto:     ipProtoTCP,
		Comm:      [4]byte{'t', 'c', 'p', '4'},
	}

	_ = bpfRingbufOutput(unsafe.Pointer(&events), unsafe.Pointer(&ev), uint64(unsafe.Sizeof(ev)), 0)
	return 0
}

func main() {}
