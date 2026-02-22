// Package event defines the shared data types exchanged between the
// kernel-side eBPF probe and the userspace reader via the ring buffer.
package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Size is the byte length of a serialized Event on the ring buffer.
const Size = 68

// Event is the fixed-size record emitted by the eBPF program.
// Layout must stay in sync with bpf/open.go.
type Event struct {
	PID         uint32
	RawFilename [64]byte
}

// Decode parses a raw ring buffer sample into an Event.
func Decode(raw []byte) (Event, error) {
	if len(raw) < Size {
		return Event{}, fmt.Errorf("short ringbuf record: got=%d want>=%d", len(raw), Size)
	}
	var ev Event
	ev.PID = binary.LittleEndian.Uint32(raw[0:4])
	copy(ev.RawFilename[:], raw[4:68])
	return ev, nil
}

// Filename returns the null-terminated filename as a Go string.
func (e Event) Filename() string {
	idx := bytes.IndexByte(e.RawFilename[:], 0)
	if idx < 0 {
		return string(e.RawFilename[:])
	}
	return string(e.RawFilename[:idx])
}
