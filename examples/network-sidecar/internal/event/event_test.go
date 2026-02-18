package event

import "testing"

func TestDecode(t *testing.T) {
	raw := []byte{
		0x39, 0x30, 0x00, 0x00, // pid 12345
		0x5d, 0xb8, 0xd8, 0x22, // 93.184.216.34 (network order bytes in little-endian word)
		0x01, 0xbb, // port 443 (network order)
		0x06, // proto tcp
		0x00,
		't', 'c', 'p', '4',
	}
	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if ev.PID != 12345 {
		t.Fatalf("unexpected pid: %d", ev.PID)
	}
	if ev.Port() != 443 {
		t.Fatalf("unexpected port: %d", ev.Port())
	}
	if got := ev.IP().String(); got != "93.184.216.34" {
		t.Fatalf("unexpected ip: %s", got)
	}
}
