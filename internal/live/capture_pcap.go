//go:build !windows && cgo
// +build !windows,cgo

package live

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func (r *runner) captureInterface(ctx context.Context, ifaceName string, policyName string, outputDir string) error {
	r.loggers.Info.Printf("OpenLive interface: %s", ifaceName)

	handle, err := pcap.OpenLive(ifaceName, r.snapLen, r.promisc, r.readTimeout)
	if err != nil {
		return fmt.Errorf("open live interface %s: %w", ifaceName, err)
	}
	defer handle.Close()
	linkType := handle.LinkType()

	if err := handle.SetBPFFilter(r.filter); err != nil {
		return fmt.Errorf("set bpf filter on %s: %w", ifaceName, err)
	}

	var pcapWriter *pcapgo.Writer
	var pcapFile *os.File
	var pcapPath string
	saveGate := newSaveWindow(r.saveWindow)
	if r.savePcap {
		fileName := fmt.Sprintf("capture_paasau_%s_%s.pcap", ifaceName, time.Now().Format("060102_150405"))
		pcapPath = filepath.Join(outputDir, fileName)
	}
	defer func() {
		if pcapFile != nil {
			pcapFile.Close()
		}
	}()

	for {
		if ctx.Err() != nil {
			return nil
		}

		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if ctx.Err() != nil || errors.Is(err, pcap.NextErrorReadError) {
				return nil
			}
			return fmt.Errorf("read packet on %s: %w", ifaceName, err)
		}

		now := time.Now()
		dstIP, ok := extractIPv4Destination(data, linkType)
		if ok {
			r.handlePacket(ctx, dstIP, ifaceName, policyName, saveGate, now)
		}
		if err := writeCapturedPacket(&pcapFile, &pcapWriter, pcapPath, linkType, r.snapLen, saveGate, r.savePcap, ci, data, now); err != nil {
			return err
		}
	}
}
