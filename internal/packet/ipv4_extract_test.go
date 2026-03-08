package packet

import (
	"net"
	"testing"
)

func TestExtractIPv4DestinationEthernet(t *testing.T) {
	packet := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0,
		1, 2, 3, 4,
		8, 8, 8, 8,
	}

	ip, ok := ExtractIPv4Destination(packet, linkTypeEthernet)
	if !ok {
		t.Fatal("expected ipv4 destination")
	}
	if !ip.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("unexpected ip: %v", ip)
	}
}

func TestExtractIPv4DestinationRaw(t *testing.T) {
	packet := []byte{
		0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0,
		1, 2, 3, 4,
		9, 9, 9, 9,
	}

	ip, ok := ExtractIPv4Destination(packet, linkTypeRaw)
	if !ok {
		t.Fatal("expected ipv4 destination")
	}
	if !ip.Equal(net.IPv4(9, 9, 9, 9)) {
		t.Fatalf("unexpected ip: %v", ip)
	}
}

func TestExtractIPv4DestinationLinuxSLL2(t *testing.T) {
	packet := []byte{
		0x08, 0x00, 0x00, 0x00, 0, 0, 0, 0,
		0, 1, 0, 6, 0x02, 0x00, 0, 0,
		0x10, 0x2d, 0, 0,
		0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0,
		1, 2, 3, 4,
		11, 22, 33, 44,
	}

	ip, ok := ExtractIPv4Destination(packet, linkTypeLinuxSLL2)
	if !ok {
		t.Fatal("expected ipv4 destination")
	}
	if !ip.Equal(net.IPv4(11, 22, 33, 44)) {
		t.Fatalf("unexpected ip: %v", ip)
	}
}
