package event

import "testing"

func TestDecode(t *testing.T) {
	raw := make([]byte, Size)
	raw[0] = 0x39
	raw[1] = 0x30 // pid 12345
	raw[4] = 0xE8
	raw[5] = 0x03 // uid 1000
	raw[8] = 0x02 // flags O_RDWR
	copy(raw[16:32], "curl\x00")
	copy(raw[32:96], "/etc/hosts\x00")

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
	if ev.Flags != 2 {
		t.Fatalf("unexpected flags: %d", ev.Flags)
	}
	if got := ev.CommString(); got != "curl" {
		t.Fatalf("unexpected comm: %q", got)
	}
	if got := ev.FilenameString(); got != "/etc/hosts" {
		t.Fatalf("unexpected filename: %q", got)
	}
}

func TestDecodeShort(t *testing.T) {
	_, err := Decode(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short record")
	}
}
