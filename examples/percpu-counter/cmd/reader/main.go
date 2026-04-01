package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	pcloader "github.com/kyleseneker/tinybpf/examples/percpu-counter/internal/loader"
)

func main() {
	var objectPath string
	flag.StringVar(&objectPath, "object", "build/counter.bpf.o", "Path to BPF object built by tinybpf.")
	flag.Parse()

	loaded, err := pcloader.LoadAndAttach(objectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load/attach: %v\n", err)
		os.Exit(1)
	}
	defer loaded.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stdout, "attached tracepoint raw_syscalls/sys_enter from %s\n", objectPath)
	fmt.Fprintln(os.Stdout, "press Ctrl+C to stop")

	ncpu := runtime.NumCPU()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var prevTotal uint64
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stdout, "detaching tracepoint program")
			return
		case <-ticker.C:
			var key uint32
			values := make([]byte, 8*ncpu)
			if err := loaded.CountersMap.Lookup(key, &values); err != nil {
				fmt.Fprintf(os.Stderr, "lookup error: %v\n", err)
				continue
			}
			var total uint64
			for cpu := 0; cpu < ncpu; cpu++ {
				off := cpu * 8
				total += binary.LittleEndian.Uint64(values[off : off+8])
			}
			rate := total - prevTotal
			prevTotal = total
			fmt.Fprintf(os.Stdout, "%s syscalls/s=%d total=%d cpus=%d\n",
				time.Now().Format(time.RFC3339), rate, total, ncpu)
		}
	}
}
