// Package loader handles loading the compiled eBPF object into the kernel
// and attaching the cgroup/connect4 program to a cgroup.
package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Loaded holds the resources obtained after a successful load and attach.
type Loaded struct {
	Objects         *ebpf.Collection
	Link            link.Link
	BlockedAddrsMap *ebpf.Map
}

// LoadAndAttach loads the eBPF collection from objectPath, attaches the
// cgroup/connect4 program to the given cgroup path, and returns a handle
// to the loaded resources.
func LoadAndAttach(objectPath, cgroupPath string) (*Loaded, error) {
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
		return nil, fmt.Errorf("could not find cgroup program in object")
	}

	cgLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach cgroup/connect4: %w", err)
	}

	blockedAddrs := coll.Maps["blocked_addrs"]
	if blockedAddrs == nil {
		_ = cgLink.Close()
		coll.Close()
		return nil, fmt.Errorf("hash map %q not found in object", "blocked_addrs")
	}

	return &Loaded{
		Objects:         coll,
		Link:            cgLink,
		BlockedAddrsMap: blockedAddrs,
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

func firstProgram(coll *ebpf.Collection) *ebpf.Program {
	for _, p := range coll.Programs {
		return p
	}
	return nil
}
