package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Size is the byte length of a FileOpenEvent as emitted by the BPF program.
const Size = 24

// FileOpenEvent mirrors the fileOpenEvent struct in the BPF program.
type FileOpenEvent struct {
	PID  uint32
	UID  uint32
	Comm [16]byte
}

// Decode parses a raw ring buffer record into a FileOpenEvent.
func Decode(raw []byte) (FileOpenEvent, error) {
	if len(raw) < Size {
		return FileOpenEvent{}, fmt.Errorf("short ringbuf record: got=%d want>=%d", len(raw), Size)
	}
	var ev FileOpenEvent
	ev.PID = binary.LittleEndian.Uint32(raw[0:4])
	ev.UID = binary.LittleEndian.Uint32(raw[4:8])
	copy(ev.Comm[:], raw[8:24])
	return ev, nil
}

// CommString returns the command name as a null-terminated string.
func (e FileOpenEvent) CommString() string {
	idx := bytes.IndexByte(e.Comm[:], 0)
	if idx < 0 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:idx])
}
