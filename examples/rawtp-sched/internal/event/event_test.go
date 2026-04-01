package event

import "testing"

func TestDecode(t *testing.T) {
	raw := make([]byte, Size)
	raw[0] = 0x39
	raw[1] = 0x30
	copy(raw[4:8], []byte{0x01, 0x00, 0x00, 0x00})
	copy(raw[8:], "bash\x00")

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if ev.Pid != 12345 {
		t.Fatalf("unexpected pid: %d", ev.Pid)
	}
	if ev.Tgid != 1 {
		t.Fatalf("unexpected tgid: %d", ev.Tgid)
	}
	if got := ev.CommString(); got != "bash" {
		t.Fatalf("unexpected comm: %q", got)
	}
}

func TestDecodeShort(t *testing.T) {
	_, err := Decode(make([]byte, Size-1))
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}
