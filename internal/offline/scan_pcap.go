//go:build cgo
// +build cgo

package offline

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/google/gopacket/pcap"

	"paasau/internal/detect"
	"paasau/internal/packet"
)

func scanPcapFile(path string, detector *detect.Detector) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	seen := make(map[string]struct{})
	linkType, err := readLinkType(path)
	if err != nil {
		linkType = int(handle.LinkType())
	}
	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) || err == pcap.NextErrorNoMorePackets {
				break
			}
			return err
		}

		ip, ok := packet.ExtractIPv4Destination(data, linkType)
		if !ok {
			continue
		}

		ipStr := ip.String()
		if _, ok := seen[ipStr]; ok {
			continue
		}
		seen[ipStr] = struct{}{}

		result, err := detector.Evaluate(net.ParseIP(ipStr))
		if err != nil {
			fmt.Printf("  lookup failed for %s: %v\n", ipStr, err)
			continue
		}
		if result.Allowed {
			continue
		}

		fmt.Printf("  violated ip=%s country=%s\n", result.IP, result.Country)
	}

	return nil
}

func readLinkType(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	header := make([]byte, 24)
	if _, err := io.ReadFull(file, header); err != nil {
		return 0, err
	}

	switch {
	case header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1:
		return int(binary.LittleEndian.Uint32(header[20:24])), nil
	case header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1:
		return int(binary.LittleEndian.Uint32(header[20:24])), nil
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4:
		return int(binary.BigEndian.Uint32(header[20:24])), nil
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d:
		return int(binary.BigEndian.Uint32(header[20:24])), nil
	default:
		return 0, fmt.Errorf("unsupported pcap header magic: % x", header[0:4])
	}
}
