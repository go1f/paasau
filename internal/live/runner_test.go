//go:build !windows
// +build !windows

package live

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"paasau/internal/cache"
	"paasau/internal/detect"
	"paasau/internal/output"
)

type fakeDetector struct {
	result detect.Result
	err    error
}

func (d fakeDetector) Evaluate(net.IP) (detect.Result, error) {
	return d.result, d.err
}

func TestHandlePacketDedupesViolationLogs(t *testing.T) {
	loggers, resultPath := newTestLoggers(t)

	r := &runner{
		loggers:          loggers,
		detector:         fakeDetector{result: detect.Result{IP: "8.8.8.8", Country: "US", Allowed: false}},
		violationTracker: cache.NewTTLSet(16, time.Minute),
		finder:           &processFinder{},
	}

	window := newSaveWindow(time.Second)
	now := time.Now()
	r.handlePacket(context.Background(), net.IPv4(8, 8, 8, 8), "wlan0", "china-car", window, now)
	r.handlePacket(context.Background(), net.IPv4(8, 8, 8, 8), "wlan0", "china-car", window, now.Add(10*time.Millisecond))

	if err := loggers.Close(); err != nil {
		t.Fatalf("close loggers: %v", err)
	}

	content, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("read result log: %v", err)
	}
	if got := strings.Count(string(content), "Violated IP: 8.8.8.8"); got != 1 {
		t.Fatalf("expected one violation log, got %d\n%s", got, string(content))
	}
	if !window.Active(now.Add(100 * time.Millisecond)) {
		t.Fatal("save window should be active after violation")
	}
}

func TestWriteCapturedPacketCreatesPcap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcap")
	window := newSaveWindow(time.Second)
	now := time.Now()
	window.Trigger(now)

	var file *os.File
	var writer *pcapgo.Writer
	packet := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 8, 8, 8, 8}
	ci := gopacket.CaptureInfo{
		Timestamp:     now,
		CaptureLength: len(packet),
		Length:        len(packet),
	}

	if err := writeCapturedPacket(&file, &writer, path, layers.LinkTypeRaw, 65536, window, true, ci, packet, now); err != nil {
		t.Fatalf("writeCapturedPacket() error = %v", err)
	}
	if file == nil || writer == nil {
		t.Fatal("expected capture writer to be created")
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close capture file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pcap file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected non-empty pcap file")
	}
}

func TestProcessFinderCooldownSkipsRepeatedLookups(t *testing.T) {
	loggers, _ := newTestLoggers(t)
	defer loggers.Close()

	var calls atomic.Int32
	finder := &processFinder{
		logger:          loggers,
		sem:             make(chan struct{}, 1),
		timeout:         time.Second,
		cooldownTracker: cache.NewTTLSet(16, time.Minute),
		enabled:         true,
		lookupFn: func(context.Context, string) (string, error) {
			calls.Add(1)
			return "matched\n", nil
		},
	}

	finder.Find(context.Background(), "8.8.8.8")
	finder.Find(context.Background(), "8.8.8.8")

	waitFor(t, time.Second, func() bool {
		return calls.Load() == 1
	})
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("expected one lookup, got %d", calls.Load())
	}
}

func newTestLoggers(t *testing.T) (*output.Loggers, string) {
	t.Helper()

	dir := t.TempDir()
	loggers, err := output.New(dir, false)
	if err != nil {
		t.Fatalf("output.New() error = %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "result_paasau_*.log"))
	if err != nil {
		t.Fatalf("glob result logs: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one result log, got %d", len(matches))
	}
	return loggers, matches[0]
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not satisfied before timeout")
}
