// Package reader consumes events from an eBPF ring buffer map and writes
// decoded open records to an output stream.
package reader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kyleseneker/tinybpf/examples/fentry-open/internal/event"
)

// Run reads from the ring buffer until ctx is cancelled, decoding each
// sample and writing the formatted event to out.
func Run(ctx context.Context, eventsMap *ebpf.Map, out io.Writer) error {
	rb, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}
	defer rb.Close()

	go func() {
		<-ctx.Done()
		_ = rb.Close()
	}()

	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}
		ev, err := event.Decode(record.RawSample)
		if err != nil {
			fmt.Fprintf(out, "decode error: %v\n", err)
			continue
		}
		fmt.Fprintf(out, "%s pid=%d file=%s\n",
			time.Now().Format(time.RFC3339Nano),
			ev.PID,
			ev.Filename(),
		)
	}
}
