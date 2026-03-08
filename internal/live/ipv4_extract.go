//go:build !windows
// +build !windows

package live

import (
	"net"

	"github.com/google/gopacket/layers"

	"paasau/internal/packet"
)

func extractIPv4Destination(data []byte, linkType layers.LinkType) (net.IP, bool) {
	return packet.ExtractIPv4Destination(data, int(linkType))
}
