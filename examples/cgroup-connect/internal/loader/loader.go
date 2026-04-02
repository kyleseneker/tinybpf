// Package loader handles loading the compiled eBPF object into the kernel
// and attaching the cgroup/connect4 program.
package loader

import (
	"fmt"

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
	CheckConnect4 *ebpf.Program `ebpf:"check_connect4"`
}

// Maps contains all BPF maps.
type Maps struct {
	BlockedAddrs *ebpf.Map `ebpf:"blocked_addrs"`
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
	if p.CheckConnect4 != nil {
		_ = p.CheckConnect4.Close()
	}
}

// Close releases all maps.
func (m *Maps) Close() {
	if m.BlockedAddrs != nil {
		_ = m.BlockedAddrs.Close()
	}
}

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects         *Objects
	Link            link.Link
	BlockedAddrsMap *ebpf.Map
}

// LoadAndAttach loads the eBPF collection from objectPath and attaches the
// cgroup/connect4 program to the given cgroup path.
func LoadAndAttach(objectPath, cgroupPath string) (*Loaded, error) {
	objs, err := Load(objectPath)
	if err != nil {
		return nil, err
	}

	cgLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CheckConnect4,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach cgroup/connect4: %w", err)
	}

	return &Loaded{
		Objects:         objs,
		Link:            cgLink,
		BlockedAddrsMap: objs.BlockedAddrs,
	}, nil
}

// Close detaches the cgroup program and releases all kernel resources.
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
