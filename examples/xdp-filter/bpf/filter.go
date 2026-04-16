// Compiled by TinyGo; see filter_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const (
	ethPIPv4 = 0x0800

	xdpPass = 2
	xdpDrop = 1

	bpfMapTypeHash = 1

	ethHLen      = 14 // sizeof(ethhdr)
	ethProtoOff  = 12 // offset of h_proto within ethhdr
	ipSrcAddrOff = 12 // offset of src_addr within iphdr
)

type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// blocklist is a hash map keyed by IPv4 source address (4 bytes).
// Userspace inserts addresses to block; the XDP program drops matching packets.
var blocklist = bpfMapDef{
	Type:       bpfMapTypeHash,
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: 1024,
}

//go:extern bpf_map_lookup_elem
func bpfMapLookupElem(mapPtr unsafe.Pointer, key unsafe.Pointer) unsafe.Pointer

//go:extern bpf_xdp_load_bytes
func bpfXdpLoadBytes(xdpMD unsafe.Pointer, offset uint32, buf unsafe.Pointer, size uint32) int64

// xdp_filter drops packets whose IPv4 source address is in the blocklist map.
//
// Uses bpf_xdp_load_bytes for verifier-friendly bounds-safe packet reads
// rather than raw pointer arithmetic on md.Data.
//
//export xdp_filter
func xdp_filter(ctx unsafe.Pointer) int32 {
	var proto uint16
	if bpfXdpLoadBytes(ctx, ethProtoOff, unsafe.Pointer(&proto), 2) != 0 {
		return xdpPass
	}
	if ntohs(proto) != ethPIPv4 {
		return xdpPass
	}

	var srcAddr uint32
	if bpfXdpLoadBytes(ctx, ethHLen+ipSrcAddrOff, unsafe.Pointer(&srcAddr), 4) != 0 {
		return xdpPass
	}

	if bpfMapLookupElem(unsafe.Pointer(&blocklist), unsafe.Pointer(&srcAddr)) != nil {
		return xdpDrop
	}
	return xdpPass
}

func ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}
