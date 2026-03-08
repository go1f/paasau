//go:build !windows
// +build !windows

package live

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/shirou/gopsutil/process"

	"paasau/internal/cache"
	"paasau/internal/config"
	"paasau/internal/detect"
	"paasau/internal/geoip"
	"paasau/internal/output"
)

type Options struct {
	PolicyName  string
	Interfaces  []string
	OutputDir   string
	GeoIPDB     string
	BPFFilter   string
	SavePcap    bool
	FindProcess bool
	ProcessName string
}

type runner struct {
	loggers          *output.Loggers
	detector         packetDetector
	filter           string
	savePcap         bool
	saveWindow       time.Duration
	snapLen          int32
	promisc          bool
	readTimeout      time.Duration
	violationTracker *cache.TTLSet
	finder           *processFinder
}

type packetDetector interface {
	Evaluate(net.IP) (detect.Result, error)
}

func Run(ctx context.Context, cfg *config.Config, opts Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	policyName, policy, err := cfg.Policy(opts.PolicyName, cfg.Live.DefaultPolicy)
	if err != nil {
		return err
	}

	outputDir := pickString(opts.OutputDir, cfg.Runtime.OutputDir)
	loggers, err := output.New(outputDir, cfg.Runtime.Debug)
	if err != nil {
		return err
	}
	defer loggers.Close()

	dbPath := pickString(opts.GeoIPDB, cfg.Live.GeoIPDB)
	reader, err := geoip.Open(dbPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	findProcess := cfg.Live.FindProcess || opts.FindProcess || strings.TrimSpace(opts.ProcessName) != ""
	var matcher *regexp.Regexp
	if strings.TrimSpace(opts.ProcessName) != "" {
		matcher, err = regexp.Compile("(?i)" + opts.ProcessName)
		if err != nil {
			return fmt.Errorf("compile process name regexp: %w", err)
		}
	}

	r := &runner{
		loggers:          loggers,
		detector:         detect.New(reader, policy, cfg.Live.GeoIPCacheSize, time.Duration(cfg.Live.GeoIPCacheTTLSeconds)*time.Second),
		filter:           pickString(opts.BPFFilter, cfg.Live.BPFFilter),
		savePcap:         cfg.Live.SavePcap || opts.SavePcap,
		saveWindow:       time.Duration(cfg.Live.SavePcapWindowSeconds) * time.Second,
		snapLen:          cfg.Live.SnapLen,
		promisc:          cfg.Live.Promisc,
		readTimeout:      time.Duration(cfg.Live.ReadTimeoutMillis) * time.Millisecond,
		violationTracker: cache.NewTTLSet(cfg.Live.ViolationCacheSize, time.Duration(cfg.Live.ViolationCooldownSeconds)*time.Second),
		finder: &processFinder{
			logger:          loggers,
			policyName:      policyName,
			sem:             make(chan struct{}, cfg.Live.WorkerLimit),
			timeout:         time.Duration(cfg.Live.ProcessLookupTimeoutSeconds) * time.Second,
			cooldownTracker: cache.NewTTLSet(cfg.Live.ProcessLookupCacheSize, time.Duration(cfg.Live.ProcessLookupCooldownSeconds)*time.Second),
			matcher:         matcher,
			enabled:         findProcess,
		},
	}

	interfaces, err := resolveInterfaces(opts.Interfaces)
	if err != nil {
		return err
	}
	if len(interfaces) == 0 {
		return fmt.Errorf("no interfaces available")
	}

	loggers.Info.Printf("Policy: %s", policyName)
	loggers.Info.Printf("GeoIP DB: %s", dbPath)
	loggers.Info.Printf("BPF filter: %s", r.filter)
	loggers.Info.Printf("Press Ctrl-C to stop live capture")

	var wg sync.WaitGroup
	errCh := make(chan error, len(interfaces))
	for _, iface := range interfaces {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if err := r.captureInterface(ctx, name, policyName, outputDir); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}(iface)
	}

	select {
	case <-ctx.Done():
		wg.Wait()
		return nil
	case err := <-errCh:
		cancel()
		wg.Wait()
		return err
	}
}

func (r *runner) handlePacket(ctx context.Context, dstIP net.IP, ifaceName string, policyName string, saveGate *saveWindow, now time.Time) {
	result, err := r.detector.Evaluate(dstIP)
	if err != nil {
		r.loggers.Debug.Printf("evaluate packet dst=%s iface=%s: %v", dstIP.String(), ifaceName, err)
		return
	}
	if result.Allowed {
		return
	}

	if saveGate != nil {
		saveGate.Trigger(now)
	}

	if !r.violationTracker.Allow(ifaceName + "|" + result.IP) {
		return
	}
	r.loggers.Info.Printf("Violated IP: %s country=%s iface=%s policy=%s", result.IP, result.Country, ifaceName, policyName)
	r.finder.Find(ctx, result.IP)
}

func writeCapturedPacket(
	pcapFile **os.File,
	pcapWriter **pcapgo.Writer,
	pcapPath string,
	linkType layers.LinkType,
	snapLen int32,
	saveGate *saveWindow,
	savePcap bool,
	ci gopacket.CaptureInfo,
	data []byte,
	now time.Time,
) error {
	if !savePcap || !saveGate.Active(now) {
		return nil
	}

	if *pcapWriter == nil {
		file, err := os.Create(pcapPath)
		if err != nil {
			return fmt.Errorf("create pcap file %s: %w", pcapPath, err)
		}
		writer := pcapgo.NewWriter(file)
		if err := writer.WriteFileHeader(uint32(snapLen), linkType); err != nil {
			file.Close()
			return fmt.Errorf("write pcap header %s: %w", pcapPath, err)
		}
		*pcapFile = file
		*pcapWriter = writer
	}

	if err := (*pcapWriter).WritePacket(ci, data); err != nil {
		return fmt.Errorf("write captured packet: %w", err)
	}
	return nil
}

func resolveInterfaces(explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		names = append(names, iface.Name)
	}
	return names, nil
}

func pickString(override string, fallback string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	return fallback
}

type processFinder struct {
	logger          *output.Loggers
	policyName      string
	sem             chan struct{}
	timeout         time.Duration
	cooldownTracker *cache.TTLSet
	lookupFn        func(context.Context, string) (string, error)
	matcher         *regexp.Regexp
	enabled         bool
	active          sync.Map
}

func (p *processFinder) Find(ctx context.Context, ip string) {
	if !p.enabled {
		return
	}
	if !p.cooldownTracker.Allow(ip) {
		return
	}
	if _, exists := p.active.LoadOrStore(ip, true); exists {
		return
	}

	go func() {
		defer p.active.Delete(ip)

		select {
		case p.sem <- struct{}{}:
			defer func() { <-p.sem }()
		case <-ctx.Done():
			return
		default:
			p.logger.Debug.Printf("Skip process lookup because workers are busy for %s", ip)
			return
		}

		lookupCtx, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()

		start := time.Now()
		lookup := p.lookup
		if p.lookupFn != nil {
			lookup = p.lookupFn
		}
		message, err := lookup(lookupCtx, ip)
		if err != nil {
			p.logger.Debug.Printf("Process lookup failed for %s: %v", ip, err)
			return
		}
		p.logger.Info.Print(message)
		p.logger.Debug.Printf("Process lookup finished in %s", time.Since(start))
	}()
}

func (p *processFinder) lookup(ctx context.Context, ip string) (string, error) {
	processes, err := process.Processes()
	if err != nil {
		return "", fmt.Errorf("list processes: %w", err)
	}

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		if p.matcher != nil {
			name, err := proc.Name()
			if err != nil || !p.matcher.MatchString(name) {
				continue
			}
		}

		conns, err := proc.Connections()
		if err != nil {
			continue
		}
		for _, conn := range conns {
			if conn.Raddr.IP != ip {
				continue
			}
			processName, _ := proc.Name()
			processPath, _ := proc.Exe()
			return fmt.Sprintf(
				"Violated process: %s(%s), pid=%d, src=%s:%d, dst=%s:%d\n",
				processName, processPath, proc.Pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port,
			), nil
		}
	}

	return fmt.Sprintf("Miss process matched: %s\n", ip), nil
}
