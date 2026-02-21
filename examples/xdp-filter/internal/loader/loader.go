// Package loader handles loading the compiled eBPF XDP object into the kernel
// and attaching it to a network interface.
package loader

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects      *ebpf.Collection
	Link         link.Link
	BlocklistMap *ebpf.Map
}

// LoadAndAttach loads the eBPF collection from objectPath and attaches the
// XDP program to the given network interface.
func LoadAndAttach(objectPath, iface string) (*Loaded, error) {
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
		return nil, fmt.Errorf("could not find XDP program in object")
	}

	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceObj.Index,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach XDP to %s: %w", iface, err)
	}

	blocklist := coll.Maps["blocklist"]
	if blocklist == nil {
		_ = xdpLink.Close()
		coll.Close()
		return nil, fmt.Errorf("blocklist map not found in object")
	}

	return &Loaded{
		Objects:      coll,
		Link:         xdpLink,
		BlocklistMap: blocklist,
	}, nil
}

// Close detaches the XDP program and releases all kernel resources.
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
