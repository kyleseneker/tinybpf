package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kyleseneker/tinybpf/examples/tc-filter/internal/loader"
)

func main() {
	var (
		objectPath string
		iface      string
		port       uint
	)
	flag.StringVar(&objectPath, "object", "build/filter.bpf.o", "Path to BPF object built by tinybpf.")
	flag.StringVar(&iface, "iface", "eth0", "Network interface to attach the TC classifier to.")
	flag.UintVar(&port, "port", 8080, "Destination port to block.")
	flag.Parse()

	loaded, err := loader.LoadAndAttach(objectPath, iface, uint16(port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load/attach: %v\n", err)
		os.Exit(1)
	}
	defer loaded.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stdout, "attached TC classifier to %s; blocking port %d\n", iface, port)
	fmt.Fprintln(os.Stdout, "press Ctrl+C to detach and exit")

	<-ctx.Done()
	fmt.Fprintln(os.Stdout, "\ndetaching TC classifier")
}
