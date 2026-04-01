package event

import "testing"

func TestDecode(t *testing.T) {
	raw := make([]byte, Size)
	raw[0] = 0x39
	raw[1] = 0x30
	raw[4] = 0xE8
	raw[5] = 0x03
	copy(raw[8:], "nginx\x00")

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if ev.PID != 12345 {
		t.Fatalf("unexpected pid: %d", ev.PID)
	}
	if ev.UID != 1000 {
		t.Fatalf("unexpected uid: %d", ev.UID)
	}
	if got := ev.CommString(); got != "nginx" {
		t.Fatalf("unexpected comm: %q", got)
	}
}

func TestDecodeShort(t *testing.T) {
	_, err := Decode(make([]byte, Size-1))
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}
