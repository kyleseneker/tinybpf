package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Objects holds the loaded BPF objects.
type Objects struct {
	prog *ebpf.Program
	link link.Link
}

// Close detaches and releases all BPF resources.
func (o *Objects) Close() error {
	if o.link != nil {
		o.link.Close()
	}
	if o.prog != nil {
		o.prog.Close()
	}
	return nil
}

// LoadAndAttach loads the BPF object and attaches to the raw tracepoint.
func LoadAndAttach(objectPath string) (*Objects, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	prog := coll.Programs["raw_tracepoint_sched_process_exec"]
	if prog == nil {
		return nil, fmt.Errorf("program raw_tracepoint_sched_process_exec not found in %s", objectPath)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: prog,
	})
	if err != nil {
		prog.Close()
		return nil, fmt.Errorf("attach raw tracepoint: %w", err)
	}

	return &Objects{prog: prog, link: tp}, nil
}
