package event

import "testing"

func TestDecode(t *testing.T) {
	raw := make([]byte, Size)
	raw[0] = 0x39 // pid 12345
	raw[1] = 0x30
	raw[4] = 0x01 // found=1

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if ev.PID != 12345 {
		t.Fatalf("unexpected pid: %d", ev.PID)
	}
	if ev.Found != 1 {
		t.Fatalf("unexpected found: %d", ev.Found)
	}
}

func TestDecodeShort(t *testing.T) {
	_, err := Decode(make([]byte, Size-1))
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}
