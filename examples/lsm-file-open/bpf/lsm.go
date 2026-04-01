// Compiled by TinyGo; see lsm_stub.go for the standard-Go IDE placeholder.

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

// events is a ring buffer for sending file-open audit events to userspace.
var events = bpfMapDef{
	Type:       bpfMapTypeRingbuf,
	MaxEntries: 1 << 24,
}

type fileOpenEvent struct {
	Pid  uint32
	Uid  uint32
	Comm [16]byte
}

//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

//go:extern bpf_get_current_uid_gid
func bpfGetCurrentUidGid() uint64

//go:extern bpf_get_current_comm
func bpfGetCurrentComm(buf unsafe.Pointer, size uint32) int32

//go:extern bpf_ringbuf_output
func bpfRingbufOutput(ringbuf unsafe.Pointer, data unsafe.Pointer, size uint64, flags uint64) int64

// lsm_file_open is an LSM hook that audits every file open.
//
//export lsm_file_open
func lsm_file_open(ctx unsafe.Pointer) int32 { //nolint:revive
	var ev fileOpenEvent
	ev.Pid = uint32(bpfGetCurrentPidTgid() >> 32)
	ev.Uid = uint32(bpfGetCurrentUidGid())
	bpfGetCurrentComm(unsafe.Pointer(&ev.Comm), 16)

	bpfRingbufOutput(unsafe.Pointer(&events), unsafe.Pointer(&ev), uint64(unsafe.Sizeof(ev)), 0)

	return 0 // allow the operation
}

func main() {}
