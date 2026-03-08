package offline

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

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

	detector := detect.New(reader, policy, cfg.Live.GeoIPCacheSize, time.Duration(cfg.Live.GeoIPCacheTTLSeconds)*time.Second)
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
		if err := scanPcapFile(pcapFile, detector); err != nil {
			fmt.Printf("  open failed: %v\n", err)
		}
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
