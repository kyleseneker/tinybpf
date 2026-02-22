// Package loader handles loading the compiled eBPF object into the kernel
// and attaching the TC classifier to the specified network interface.
package loader

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects *ebpf.Collection
	Link    link.Link
}

// LoadAndAttach loads the eBPF collection from objectPath, attaches the TC
// classifier to the ingress of iface, and populates the blocked_ports map
// with the given port in network byte order.
func LoadAndAttach(objectPath, iface string, port uint16) (*Loaded, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	prog := firstProgram(coll)
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("could not find classifier program in object")
	}

	ifObj, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Interface: ifObj.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach TC classifier to %s ingress: %w", iface, err)
	}

	blockedPorts := coll.Maps["blocked_ports"]
	if blockedPorts == nil {
		_ = tcLink.Close()
		coll.Close()
		return nil, fmt.Errorf("hash map %q not found in object", "blocked_ports")
	}

	portBE := make([]byte, 2)
	binary.BigEndian.PutUint16(portBE, port)
	val := uint8(1)
	if err := blockedPorts.Put(portBE, val); err != nil {
		_ = tcLink.Close()
		coll.Close()
		return nil, fmt.Errorf("populate blocked_ports map with port %d: %w", port, err)
	}

	return &Loaded{
		Objects: coll,
		Link:    tcLink,
	}, nil
}

// Close detaches the TC classifier and releases all kernel resources.
func (l *Loaded) Close() {
	if l == nil {
		return
	}
	if l.Link != nil {
		_ = l.Link.Close()
	}
	if l.Objects != nil {
		l.Objects.Close()
	}
}

func firstProgram(coll *ebpf.Collection) *ebpf.Program {
	for _, p := range coll.Programs {
		return p
	}
	return nil
}
