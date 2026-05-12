package offline

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	embedded "paasau"
	"paasau/internal/config"
	"paasau/internal/detect"
	"paasau/internal/geoip"
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

func TestScanPcapFileWorksWithoutLibpcap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.pcap")
	writeTestPcap(t, path, net.IPv4(1, 1, 1, 1), net.IPv4(8, 8, 8, 8))

	db, err := embedded.DefaultOfflineGeoIPDB()
	if err != nil {
		t.Fatalf("read embedded db: %v", err)
	}
	reader, err := geoip.OpenBytes("embedded test db", db)
	if err != nil {
		t.Fatalf("open embedded db: %v", err)
	}
	defer reader.Close()

	detector := detect.New(reader, config.Policy{Mode: "allowlist", Countries: []string{"CN"}}, 16, time.Minute)

	if err := scanPcapFile(path, detector); err != nil {
		t.Fatalf("scanPcapFile() error = %v", err)
	}
}

func writeTestPcap(t *testing.T, path string, srcIP net.IP, dstIP net.IP) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		DstMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, ethernet, ipv4); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Unix(0, 0),
		CaptureLength: len(buffer.Bytes()),
		Length:        len(buffer.Bytes()),
	}, buffer.Bytes()); err != nil {
		t.Fatalf("write packet: %v", err)
	}
}
