package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	schedloader "github.com/kyleseneker/tinybpf/examples/rawtp-sched/internal/loader"
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

	fmt.Fprintf(os.Stdout, "attached raw tracepoint sched_process_exec from %s\n", objectPath)
	fmt.Fprintln(os.Stdout, "press Ctrl+C to detach and exit")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stdout, "detaching raw tracepoint program")
}
