package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kyleseneker/tinybpf/examples/cgroup-connect/internal/loader"
)

func main() {
	var (
		objectPath string
		cgroupPath string
		blockIP    string
	)
	flag.StringVar(&objectPath, "object", "build/connect.bpf.o", "Path to BPF object built by tinybpf.")
	flag.StringVar(&cgroupPath, "cgroup", "/sys/fs/cgroup", "Path to cgroup v2 directory.")
	flag.StringVar(&blockIP, "block-ip", "93.184.216.34", "IPv4 address to block (dotted-decimal).")
	flag.Parse()

	ip := net.ParseIP(blockIP).To4()
	if ip == nil {
		fmt.Fprintf(os.Stderr, "invalid IPv4 address: %s\n", blockIP)
		os.Exit(1)
	}

	loaded, err := loader.LoadAndAttach(objectPath, cgroupPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load/attach: %v\n", err)
		os.Exit(1)
	}
	defer loaded.Close()

	ipKey := binary.BigEndian.Uint32(ip)
	if err := loaded.BlockedAddrsMap.Put(ipKey, uint8(1)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to populate blocked_addrs map: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "attached cgroup/connect4 to %s; blocking %s\n", cgroupPath, blockIP)
	fmt.Fprintln(os.Stdout, "press Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Fprintln(os.Stdout, "\ndetaching and exiting")
}
