//go:build cgo
// +build cgo

package offline

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"paasau/internal/detect"
)

func scanPcapFile(path string, detector *detect.Detector) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	seen := make(map[string]struct{})
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}

		ip := ipLayer.(*layers.IPv4).DstIP
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
