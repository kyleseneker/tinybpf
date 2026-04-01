package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Size is the byte length of an ExecEvent as emitted by the BPF program.
const Size = 24

// ExecEvent mirrors the execEvent struct in the BPF program.
type ExecEvent struct {
	Pid  uint32
	Tgid uint32
	Comm [16]byte
}

// Decode parses a raw perf event record into an ExecEvent.
func Decode(raw []byte) (ExecEvent, error) {
	if len(raw) < Size {
		return ExecEvent{}, fmt.Errorf("short perf record: got=%d want>=%d", len(raw), Size)
	}
	var ev ExecEvent
	ev.Pid = binary.LittleEndian.Uint32(raw[0:4])
	ev.Tgid = binary.LittleEndian.Uint32(raw[4:8])
	copy(ev.Comm[:], raw[8:24])
	return ev, nil
}

// CommString returns the command name as a null-terminated string.
func (e ExecEvent) CommString() string {
	idx := bytes.IndexByte(e.Comm[:], 0)
	if idx < 0 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:idx])
}
