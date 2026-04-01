// Package loader handles loading the compiled eBPF XDP object into the kernel
// and attaching the XDP program to the specified network interface.
package loader

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Objects contains all programs and maps from the BPF object.
type Objects struct {
	Programs
	Maps
}

// Programs contains all BPF programs.
type Programs struct {
	XdpFilter *ebpf.Program `ebpf:"xdp_filter"`
}

// Maps contains all BPF maps.
type Maps struct {
	Blocklist *ebpf.Map `ebpf:"blocklist"`
}

// Load loads the BPF object from objectPath and returns populated Objects.
func Load(objectPath string) (*Objects, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	var objs Objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load and assign: %w", err)
	}
	return &objs, nil
}

// Close releases all resources held by Objects.
func (o *Objects) Close() {
	if o == nil {
		return
	}
	o.Programs.Close()
	o.Maps.Close()
}

// Close releases all programs.
func (p *Programs) Close() {
	if p.XdpFilter != nil {
		_ = p.XdpFilter.Close()
	}
}

// Close releases all maps.
func (m *Maps) Close() {
	if m.Blocklist != nil {
		_ = m.Blocklist.Close()
	}
}

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects      *Objects
	Link         link.Link
	BlocklistMap *ebpf.Map
}

// LoadAndAttach loads the eBPF collection from objectPath and attaches the
// XDP program to the specified network interface.
func LoadAndAttach(objectPath, iface string) (*Loaded, error) {
	objs, err := Load(objectPath)
	if err != nil {
		return nil, err
	}

	ifObj, err := net.InterfaceByName(iface)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilter,
		Interface: ifObj.Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach XDP to %s: %w", iface, err)
	}

	return &Loaded{
		Objects:      objs,
		Link:         xdpLink,
		BlocklistMap: objs.Blocklist,
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
