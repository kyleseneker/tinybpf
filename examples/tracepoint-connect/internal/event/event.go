// Package event defines the shared data types exchanged between the
// kernel-side eBPF probe and the userspace reader via the ring buffer.
package event

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Size is the byte length of a serialized ConnectEvent on the ring buffer.
const Size = 16

// ConnectEvent is the fixed-size record emitted by the eBPF program.
// Layout must stay in sync with bpf/connect.go.
type ConnectEvent struct {
	PID       uint32
	DstAddrBE uint32
	DstPortBE uint16
	Proto     uint8
	_         uint8
	Comm      [4]byte
}

// Decode parses a raw ring buffer sample into a ConnectEvent.
func Decode(raw []byte) (ConnectEvent, error) {
	if len(raw) < Size {
		return ConnectEvent{}, fmt.Errorf("short ringbuf record: got=%d want>=%d", len(raw), Size)
	}
	return ConnectEvent{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		DstAddrBE: binary.LittleEndian.Uint32(raw[4:8]),
		DstPortBE: binary.LittleEndian.Uint16(raw[8:10]),
		Proto:     raw[10],
		Comm:      [4]byte{raw[12], raw[13], raw[14], raw[15]},
	}, nil
}

// IP converts the big-endian destination address into a net.IP.
func (e ConnectEvent) IP() net.IP {
	b := []byte{
		byte(e.DstAddrBE),
		byte(e.DstAddrBE >> 8),
		byte(e.DstAddrBE >> 16),
		byte(e.DstAddrBE >> 24),
	}
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// Port converts the big-endian destination port to host byte order.
func (e ConnectEvent) Port() uint16 {
	return (e.DstPortBE << 8) | (e.DstPortBE >> 8)
}
