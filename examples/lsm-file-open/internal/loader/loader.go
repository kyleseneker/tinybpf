package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Loaded holds loaded BPF objects and their kernel attachment.
type Loaded struct {
	Objects   *ebpf.Collection
	Link      link.Link
	EventsMap *ebpf.Map
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

// LoadAndAttach loads the BPF object and attaches the LSM hook.
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

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: prog,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach LSM: %w", err)
	}

	events := coll.Maps["events"]
	if events == nil {
		lsmLink.Close()
		coll.Close()
		return nil, fmt.Errorf("ring buffer map %q not found in object", "events")
	}

	return &Loaded{
		Objects:   coll,
		Link:      lsmLink,
		EventsMap: events,
	}, nil
}

func firstProgram(coll *ebpf.Collection) *ebpf.Program {
	for _, p := range coll.Programs {
		return p
	}
	return nil
}
