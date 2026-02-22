// Compiled by TinyGo; see filter_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const (
	ethHLen    = 14
	ipProtoTCP = 6
	ipProtoUDP = 17
	tcActOK    = 0
	tcActShot  = 2

	bpfMapTypeHash = 1
)

type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

var blocked_ports = bpfMapDef{
	Type:       bpfMapTypeHash,
	KeySize:    2,
	ValueSize:  1,
	MaxEntries: 1024,
}

//go:extern bpf_map_lookup_elem
func bpfMapLookupElem(mapPtr unsafe.Pointer, key unsafe.Pointer) unsafe.Pointer

//go:extern bpf_skb_load_bytes
func bpfSkbLoadBytes(skb unsafe.Pointer, offset uint32, to unsafe.Pointer, len uint32) int64

// classify_ingress is the TC classifier entry point. //export keeps TinyGo from
// eliminating it; tinybpf assigns the classifier ELF section.
//
//export classify_ingress
func classify_ingress(skb unsafe.Pointer) int32 {
	// Read IP protocol byte (offset ETH_HLEN + 9).
	var proto uint8
	if bpfSkbLoadBytes(skb, ethHLen+9, unsafe.Pointer(&proto), 1) != 0 {
		return tcActOK
	}

	if proto != ipProtoTCP && proto != ipProtoUDP {
		return tcActOK
	}

	// IP header length is the low nibble of the first byte * 4.
	var ipVerIHL uint8
	if bpfSkbLoadBytes(skb, ethHLen, unsafe.Pointer(&ipVerIHL), 1) != 0 {
		return tcActOK
	}
	ihl := uint32(ipVerIHL&0x0F) * 4

	// Destination port is at bytes 2-3 of the TCP/UDP header (network byte order).
	var dstPort uint16
	if bpfSkbLoadBytes(skb, ethHLen+ihl+2, unsafe.Pointer(&dstPort), 2) != 0 {
		return tcActOK
	}

	val := bpfMapLookupElem(unsafe.Pointer(&blocked_ports), unsafe.Pointer(&dstPort))
	if val != nil {
		return tcActShot
	}
	return tcActOK
}

func main() {}
