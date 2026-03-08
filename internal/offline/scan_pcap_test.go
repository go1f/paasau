package offline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLinkTypeLittleEndianPcap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.pcap")
	header := []byte{
		0xd4, 0xc3, 0xb2, 0xa1,
		0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00,
		0x14, 0x01, 0x00, 0x00,
	}
	if err := os.WriteFile(path, header, 0o644); err != nil {
		t.Fatalf("write temp pcap: %v", err)
	}

	linkType, err := readLinkType(path)
	if err != nil {
		t.Fatalf("readLinkType() error = %v", err)
	}
	if linkType != 276 {
		t.Fatalf("expected 276, got %d", linkType)
	}
}
