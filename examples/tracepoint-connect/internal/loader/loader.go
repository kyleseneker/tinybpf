// Package loader handles loading the compiled eBPF object into the kernel
// and attaching the tracepoint to sys_enter_connect.
package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects   *ebpf.Collection
	Link      link.Link
	EventsMap *ebpf.Map
}

// LoadAndAttach loads the eBPF collection from objectPath, attaches the
// tracepoint program, and returns a handle to the loaded resources.
func LoadAndAttach(objectPath string) (*Loaded, error) {
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
		return nil, fmt.Errorf("could not find tracepoint program in object")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach tracepoint syscalls/sys_enter_connect: %w", err)
	}

	events := coll.Maps["events"]
	if events == nil {
		_ = tp.Close()
		coll.Close()
		return nil, fmt.Errorf("ring buffer map %q not found in object", "events")
	}

	return &Loaded{
		Objects:   coll,
		Link:      tp,
		EventsMap: events,
	}, nil
}

// Close detaches the tracepoint and releases all kernel resources.
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
