package reader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/kyleseneker/tinybpf/examples/rawtp-sched/internal/event"
)

// Run reads exec events from the perf event array until the context is cancelled.
func Run(ctx context.Context, eventsMap *ebpf.Map, out io.Writer) error {
	rd, err := perf.NewReader(eventsMap, 4096)
	if err != nil {
		return fmt.Errorf("create perf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read perf event: %w", err)
		}
		if record.LostSamples > 0 {
			fmt.Fprintf(out, "lost %d samples\n", record.LostSamples)
			continue
		}
		ev, err := event.Decode(record.RawSample)
		if err != nil {
			fmt.Fprintf(out, "decode error: %v\n", err)
			continue
		}
		fmt.Fprintf(out, "%s pid=%d tgid=%d comm=%s\n",
			time.Now().Format(time.RFC3339Nano),
			ev.Pid, ev.Tgid, ev.CommString())
	}
}
