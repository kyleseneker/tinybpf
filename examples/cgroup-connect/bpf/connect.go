// Compiled by TinyGo; see connect_stub.go for the standard-Go IDE placeholder.

//go:build tinygo

package main

import "unsafe"

const (
	bpfMapTypeHash = 1
)

type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// blocked_addrs is a hash map keyed by IPv4 destination address (network byte order).
// Userspace inserts addresses to block; the cgroup/connect4 program rejects matching connections.
var blocked_addrs = bpfMapDef{
	Type:       bpfMapTypeHash,
	KeySize:    4,
	ValueSize:  1,
	MaxEntries: 256,
}

//go:extern bpf_map_lookup_elem
func bpfMapLookupElem(mapPtr unsafe.Pointer, key unsafe.Pointer) unsafe.Pointer

// check_connect4 is the cgroup/connect4 entry point. //export keeps TinyGo from
// eliminating it; tinybpf assigns the cgroup ELF section.
//
//export check_connect4
func check_connect4(ctx unsafe.Pointer) int32 {
	// bpf_sock_addr.user_ip4 is at offset 24.
	dstIP := *(*uint32)(unsafe.Pointer(uintptr(ctx) + 24))

	val := bpfMapLookupElem(unsafe.Pointer(&blocked_addrs), unsafe.Pointer(&dstIP))
	if val != nil {
		return 0 // block
	}
	return 1 // allow
}

func main() {}
