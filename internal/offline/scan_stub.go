//go:build !cgo
// +build !cgo

package offline

import (
	"fmt"

	"paasau/internal/detect"
)

func scanPcapFile(string, *detect.Detector) error {
	return fmt.Errorf("offline pcap scanning requires cgo/libpcap support")
}
