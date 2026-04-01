package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	schedloader "github.com/kyleseneker/tinybpf/examples/rawtp-sched/internal/loader"
	"github.com/kyleseneker/tinybpf/examples/rawtp-sched/internal/reader"
)

func main() {
	var objectPath string
	flag.StringVar(&objectPath, "object", "build/sched.bpf.o", "Path to BPF object built by tinybpf.")
	flag.Parse()

	loaded, err := schedloader.LoadAndAttach(objectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load/attach: %v\n", err)
		os.Exit(1)
	}
	defer loaded.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stdout, "attached raw tracepoint sched_process_exec from %s\n", objectPath)
	fmt.Fprintln(os.Stdout, "press Ctrl+C to stop")

	if err := reader.Run(ctx, loaded.EventsMap, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "reader error: %v\n", err)
		os.Exit(1)
	}
}
