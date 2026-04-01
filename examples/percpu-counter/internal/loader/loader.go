package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Loaded holds loaded BPF objects and their kernel attachment.
type Loaded struct {
	Objects     *ebpf.Collection
	Link        link.Link
	CountersMap *ebpf.Map
}

// Close detaches and releases all BPF resources.
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

// LoadAndAttach loads the BPF object and attaches the tracepoint.
func LoadAndAttach(objectPath string) (*Loaded, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	prog := firstProgram(coll)
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("no programs found in %s", objectPath)
	}

	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	counters := coll.Maps["counters"]
	if counters == nil {
		tp.Close()
		coll.Close()
		return nil, fmt.Errorf("counters map not found in object")
	}

	return &Loaded{
		Objects:     coll,
		Link:        tp,
		CountersMap: counters,
	}, nil
}

func firstProgram(coll *ebpf.Collection) *ebpf.Program {
	for _, p := range coll.Programs {
		return p
	}
	return nil
}
