package offline

import (
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"paasau/internal/config"
	"paasau/internal/detect"
	"paasau/internal/geoip"
)

type Options struct {
	PolicyName string
	GeoIPDB    string
	InputDir   string
}

func Run(cfg *config.Config, opts Options) error {
	policyName, policy, err := cfg.Policy(opts.PolicyName, cfg.Offline.DefaultPolicy)
	if err != nil {
		return err
	}

	dbPath := pickString(opts.GeoIPDB, cfg.Offline.GeoIPDB)
	reader, err := geoip.Open(dbPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	detector := detect.New(reader, policy)
	pcapFiles, err := getPcapFiles(opts.InputDir)
	if err != nil {
		return err
	}
	if len(pcapFiles) == 0 {
		return fmt.Errorf("no pcap files found under %s", opts.InputDir)
	}

	fmt.Printf("Scanning %d file(s) with policy=%s db=%s\n\n", len(pcapFiles), policyName, dbPath)

	for _, pcapFile := range pcapFiles {
		fmt.Printf("Handling %s:\n", pcapFile)

		handle, err := pcap.OpenOffline(pcapFile)
		if err != nil {
			fmt.Printf("  open failed: %v\n\n", err)
			continue
		}

		seen := make(map[string]struct{})
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}

			ip := ipLayer.(*layers.IPv4).DstIP
			if _, ok := seen[ip.String()]; ok {
				continue
			}
			seen[ip.String()] = struct{}{}

			result, err := detector.Evaluate(net.ParseIP(ip.String()))
			if err != nil {
				fmt.Printf("  lookup failed for %s: %v\n", ip.String(), err)
				continue
			}
			if result.Allowed {
				continue
			}

			fmt.Printf("  violated ip=%s country=%s\n", result.IP, result.Country)
		}

		handle.Close()
		fmt.Println()
	}

	return nil
}

func getPcapFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".pcap" || ext == ".pcapng" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk pcap dir %s: %w", root, err)
	}
	return files, nil
}

func pickString(override string, fallback string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	return fallback
}
