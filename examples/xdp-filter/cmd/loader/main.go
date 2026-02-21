package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	xdploader "github.com/kyleseneker/tinybpf/examples/xdp-filter/internal/loader"
)

func main() {
	var (
		objectPath string
		iface      string
		blockIP    string
	)
	flag.StringVar(&objectPath, "object", "build/filter.bpf.o", "Path to BPF object built by tinybpf.")
	flag.StringVar(&iface, "iface", "lo", "Network interface to attach XDP program.")
	flag.StringVar(&blockIP, "block", "", "IPv4 address to add to the blocklist (optional).")
	flag.Parse()

	loaded, err := xdploader.LoadAndAttach(objectPath, iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load/attach: %v\n", err)
		os.Exit(1)
	}
	defer loaded.Close()

	fmt.Fprintf(os.Stdout, "attached XDP to %s from %s\n", iface, objectPath)

	if blockIP != "" {
		ip := net.ParseIP(blockIP).To4()
		if ip == nil {
			fmt.Fprintf(os.Stderr, "invalid IPv4 address: %s\n", blockIP)
			os.Exit(1)
		}
		key := binary.LittleEndian.Uint32(ip)
		var val uint32
		if err := loaded.BlocklistMap.Put(key, val); err != nil {
			fmt.Fprintf(os.Stderr, "failed to add %s to blocklist: %v\n", blockIP, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "added %s to blocklist\n", blockIP)
	}

	fmt.Fprintln(os.Stdout, "press Ctrl+C to detach and exit")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stdout, "detaching XDP program")
}
