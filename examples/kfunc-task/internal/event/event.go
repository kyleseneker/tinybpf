// Package event defines the shared data types exchanged between the
// kernel-side eBPF probe and the userspace reader via the ring buffer.
package event

import (
	"encoding/binary"
	"fmt"
)

// Size is the byte length of a serialized Event on the ring buffer.
const Size = 8

// Event is the fixed-size record emitted by the eBPF program.
// Layout must stay in sync with bpf/task.go.
type Event struct {
	PID   uint32
	Found uint32
}

// Decode parses a raw ring buffer sample into an Event.
func Decode(raw []byte) (Event, error) {
	if len(raw) < Size {
		return Event{}, fmt.Errorf("short ringbuf record: got=%d want>=%d", len(raw), Size)
	}
	return Event{
		PID:   binary.LittleEndian.Uint32(raw[0:4]),
		Found: binary.LittleEndian.Uint32(raw[4:8]),
	}, nil
}
