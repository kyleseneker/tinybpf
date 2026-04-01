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

// Objects contains all programs and maps from the BPF object.
type Objects struct {
	Programs
	Maps
}

// Programs contains all BPF programs.
type Programs struct {
	ClassifyIngress *ebpf.Program `ebpf:"classify_ingress"`
}

// Maps contains all BPF maps.
type Maps struct {
	BlockedPorts *ebpf.Map `ebpf:"blocked_ports"`
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
	if p.ClassifyIngress != nil {
		_ = p.ClassifyIngress.Close()
	}
}

// Close releases all maps.
func (m *Maps) Close() {
	if m.BlockedPorts != nil {
		_ = m.BlockedPorts.Close()
	}
}

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects *Objects
	Link    link.Link
}

// LoadAndAttach loads the eBPF collection from objectPath, attaches the TC
// classifier to the ingress of iface, and populates the blocked_ports map
// with the given port in network byte order.
func LoadAndAttach(objectPath, iface string, port uint16) (*Loaded, error) {
	objs, err := Load(objectPath)
	if err != nil {
		return nil, err
	}

	ifObj, err := net.InterfaceByName(iface)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Interface: ifObj.Index,
		Program:   objs.ClassifyIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach TC classifier to %s ingress: %w", iface, err)
	}

	portBE := make([]byte, 2)
	binary.BigEndian.PutUint16(portBE, port)
	val := uint8(1)
	if err := objs.BlockedPorts.Put(portBE, val); err != nil {
		_ = tcLink.Close()
		objs.Close()
		return nil, fmt.Errorf("populate blocked_ports map with port %d: %w", port, err)
	}

	return &Loaded{
		Objects: objs,
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
