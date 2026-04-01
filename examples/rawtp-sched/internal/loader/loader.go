// Package loader handles loading the compiled eBPF object into the kernel
// and attaching the raw tracepoint program.
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
	RawTracepointSchedProcessExec *ebpf.Program `ebpf:"raw_tracepoint_sched_process_exec"`
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
	if p.RawTracepointSchedProcessExec != nil {
		_ = p.RawTracepointSchedProcessExec.Close()
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

// LoadAndAttach loads the eBPF object and attaches to the raw tracepoint.
func LoadAndAttach(objectPath string) (*Loaded, error) {
	objs, err := Load(objectPath)
	if err != nil {
		return nil, err
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: objs.RawTracepointSchedProcessExec,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach raw tracepoint: %w", err)
	}

	return &Loaded{
		Objects:   objs,
		Link:      tp,
		EventsMap: objs.Events,
	}, nil
}

// Close detaches the raw tracepoint and releases all kernel resources.
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
