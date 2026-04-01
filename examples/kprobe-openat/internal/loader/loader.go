// Package loader handles loading the compiled eBPF object into the kernel
// and attaching the kprobe program to do_sys_openat2.
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
	KprobeOpenat *ebpf.Program `ebpf:"kprobe_openat"`
}

// Maps contains all BPF maps.
type Maps struct {
	Events *ebpf.Map `ebpf:"events"`
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
	if p.KprobeOpenat != nil {
		_ = p.KprobeOpenat.Close()
	}
}

// Close releases all maps.
func (m *Maps) Close() {
	if m.Events != nil {
		_ = m.Events.Close()
	}
}

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects   *Objects
	Link      link.Link
	EventsMap *ebpf.Map
}

// LoadAndAttach loads the eBPF collection from objectPath and attaches the
// kprobe program to do_sys_openat2.
func LoadAndAttach(objectPath string) (*Loaded, error) {
	objs, err := Load(objectPath)
	if err != nil {
		return nil, err
	}

	kp, err := link.Kprobe("do_sys_openat2", objs.KprobeOpenat, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach kprobe: %w", err)
	}

	return &Loaded{
		Objects:   objs,
		Link:      kp,
		EventsMap: objs.Events,
	}, nil
}

// Close detaches the kprobe program and releases all kernel resources.
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
