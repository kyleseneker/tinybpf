// Package event defines the shared data types exchanged between the
// kernel-side eBPF probe and the userspace reader via the ring buffer.
package event

import (
	"encoding/binary"
	"fmt"
)

// Size is the byte length of a serialized OpenEvent on the ring buffer.
// Must stay in sync with bpf/openat.go.
const Size = 96

// OpenEvent is the fixed-size record emitted by the kprobe program.
type OpenEvent struct {
	PID      uint32
	UID      uint32
	Flags    uint32
	_        uint32
	Comm     [16]byte
	Filename [64]byte
}

// Decode parses a raw ring buffer sample into an OpenEvent.
func Decode(raw []byte) (OpenEvent, error) {
	if len(raw) < Size {
		return OpenEvent{}, fmt.Errorf("short ringbuf record: got=%d want>=%d", len(raw), Size)
	}
	var ev OpenEvent
	ev.PID = binary.LittleEndian.Uint32(raw[0:4])
	ev.UID = binary.LittleEndian.Uint32(raw[4:8])
	ev.Flags = binary.LittleEndian.Uint32(raw[8:12])
	copy(ev.Comm[:], raw[16:32])
	copy(ev.Filename[:], raw[32:96])
	return ev, nil
}

// CommString returns the command name as a trimmed string.
func (e OpenEvent) CommString() string {
	return cstring(e.Comm[:])
}

// FilenameString returns the filename as a trimmed string.
func (e OpenEvent) FilenameString() string {
	return cstring(e.Filename[:])
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
