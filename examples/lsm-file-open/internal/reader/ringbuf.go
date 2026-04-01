package reader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/kyleseneker/tinybpf/examples/lsm-file-open/internal/event"
)

// Run reads file-open audit events from the ring buffer until the context is cancelled.
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
		fmt.Fprintf(out, "%s pid=%d uid=%d comm=%s\n",
			time.Now().Format(time.RFC3339Nano),
			ev.PID, ev.UID, ev.CommString())
	}
}
