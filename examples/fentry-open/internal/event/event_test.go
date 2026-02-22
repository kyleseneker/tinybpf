package event

import "testing"

func TestDecode(t *testing.T) {
	raw := make([]byte, Size)
	raw[0] = 0x39 // pid 12345
	raw[1] = 0x30
	raw[2] = 0x00
	raw[3] = 0x00
	copy(raw[4:], "/etc/hosts\x00")

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if ev.PID != 12345 {
		t.Fatalf("unexpected pid: %d", ev.PID)
	}
	if got := ev.Filename(); got != "/etc/hosts" {
		t.Fatalf("unexpected filename: %q", got)
	}
}

func TestDecodeShort(t *testing.T) {
	_, err := Decode(make([]byte, Size-1))
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}
