package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kyleseneker/tinybpf/examples/fentry-open/internal/loader"
	"github.com/kyleseneker/tinybpf/examples/fentry-open/internal/reader"
)

func main() {
	var objectPath string
	flag.StringVar(&objectPath, "object", "build/open.bpf.o", "Path to BPF object built by tinybpf.")
	flag.Parse()

	loaded, err := loader.LoadAndAttach(objectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load/attach: %v\n", err)
		os.Exit(1)
	}
	defer loaded.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stdout, "attached fentry/do_sys_openat2; reading events from %s\n", objectPath)
	fmt.Fprintln(os.Stdout, "press Ctrl+C to stop")
	if err := reader.Run(ctx, loaded.EventsMap, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "reader error: %v\n", err)
		os.Exit(1)
	}
}
