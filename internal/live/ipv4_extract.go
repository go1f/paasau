//go:build !windows
// +build !windows

package live

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func extractIPv4Destination(data []byte, linkType layers.LinkType) (net.IP, bool) {
	switch linkType {
	case layers.LinkTypeEthernet:
		return extractIPv4FromEthernet(data)
	case layers.LinkTypeLinuxSLL:
		return extractIPv4FromLinuxSLL(data)
	case layers.LinkTypeRaw:
		return extractIPv4FromIP(data)
	default:
		packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return nil, false
		}
		return ipLayer.(*layers.IPv4).DstIP, true
	}
}

func extractIPv4FromEthernet(data []byte) (net.IP, bool) {
	if len(data) < 14 {
		return nil, false
	}

	offset := 14
	etherType := binary.BigEndian.Uint16(data[12:14])

	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(data) < offset+4 {
			return nil, false
		}
		etherType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
	}

	if etherType != 0x0800 {
		return nil, false
	}
	return extractIPv4AtOffset(data, offset)
}

func extractIPv4FromLinuxSLL(data []byte) (net.IP, bool) {
	if len(data) < 16 {
		return nil, false
	}
	if binary.BigEndian.Uint16(data[14:16]) != 0x0800 {
		return nil, false
	}
	return extractIPv4AtOffset(data, 16)
}

func extractIPv4FromIP(data []byte) (net.IP, bool) {
	return extractIPv4AtOffset(data, 0)
}

func extractIPv4AtOffset(data []byte, offset int) (net.IP, bool) {
	if len(data) < offset+20 {
		return nil, false
	}
	if data[offset]>>4 != 4 {
		return nil, false
	}
	return net.IPv4(
		data[offset+16],
		data[offset+17],
		data[offset+18],
		data[offset+19],
	), true
}
