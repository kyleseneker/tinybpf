//go:build tinygo

package main

import "unsafe"

const (
	ethPIPv4 = 0x0800

	xdpPass = 2
	xdpDrop = 1

	bpfMapTypeHash = 1
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

type ethhdr struct {
	DstMAC [6]byte
	SrcMAC [6]byte
	Proto  uint16
}

type iphdr struct {
	VersionIHL uint8
	TOS        uint8
	TotLen     uint16
	ID         uint16
	FragOff    uint16
	TTL        uint8
	Protocol   uint8
	Check      uint16
	SrcAddr    uint32
	DstAddr    uint32
}

//go:extern bpf_map_lookup_elem
func bpfMapLookupElem(mapPtr unsafe.Pointer, key unsafe.Pointer) unsafe.Pointer

// xdp_filter drops packets whose IPv4 source address is in the blocklist map.
//
//export xdp_filter
func xdp_filter(ctx unsafe.Pointer) int32 {
	type xdpMD struct {
		Data    uint32
		DataEnd uint32
	}
	md := (*xdpMD)(ctx)

	ethSize := uint32(unsafe.Sizeof(ethhdr{}))
	if md.Data+ethSize > md.DataEnd {
		return xdpPass
	}
	eth := (*ethhdr)(unsafe.Pointer(uintptr(md.Data)))

	if ntohs(eth.Proto) != ethPIPv4 {
		return xdpPass
	}

	ipOff := md.Data + ethSize
	ipSize := uint32(unsafe.Sizeof(iphdr{}))
	if ipOff+ipSize > md.DataEnd {
		return xdpPass
	}
	ip := (*iphdr)(unsafe.Pointer(uintptr(ipOff)))

	srcAddr := ip.SrcAddr
	val := bpfMapLookupElem(unsafe.Pointer(&blocklist), unsafe.Pointer(&srcAddr))
	if val != nil {
		return xdpDrop
	}
	return xdpPass
}

func ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func main() {}
