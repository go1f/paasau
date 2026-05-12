package offline

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"

	"paasau/internal/detect"
	"paasau/internal/packet"
)

func scanPcapFile(path string, detector *detect.Detector) error {
	file, reader, linkType, err := openPacketReader(path)
	if err != nil {
		return err
	}
	defer file.Close()

	seen := make(map[string]struct{})
	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
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

type packetDataReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func openPacketReader(path string) (*os.File, packetDataReader, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, err
	}

	if strings.EqualFold(filepath.Ext(path), ".pcapng") {
		reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			file.Close()
			return nil, nil, 0, err
		}
		return file, reader, int(reader.LinkType()), nil
	}

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		file.Close()
		return nil, nil, 0, err
	}
	return file, reader, int(reader.LinkType()), nil
}
