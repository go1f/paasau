package main

import (
	"strings"
	"testing"
)

func TestRootUsageIncludesDetailedHelp(t *testing.T) {
	usage := rootUsageStringForMode("paasau", true)
	required := []string{
		"Default behavior: paasau [live flags]",
		"Live flags:",
		"Offline flags:",
		"paasau -live -h",
		"paasau -offline -h",
	}

	for _, item := range required {
		if !strings.Contains(usage, item) {
			t.Fatalf("usage missing %q:\n%s", item, usage)
		}
	}
}

func TestRootUsageWindowsOfflineOnly(t *testing.T) {
	usage := rootUsageStringForMode("paasau", false)
	required := []string{
		"Default behavior: paasau -offline <pcap-dir>",
		"-live      Not supported in Windows builds",
		"This build only supports offline scanning.",
		"paasau -offline -h",
	}
	for _, item := range required {
		if !strings.Contains(usage, item) {
			t.Fatalf("usage missing %q:\n%s", item, usage)
		}
	}
	if strings.Contains(usage, "paasau -live -h") {
		t.Fatalf("windows usage should not advertise live help:\n%s", usage)
	}
}

func TestLiveUsageListsCommonFlags(t *testing.T) {
	usage := liveUsageString("paasau")
	required := []string{
		"Usage: paasau -live [flags]",
		"-config <file>",
		"-foreign",
		"-save",
		"-who",
		"paasau -i wlan0 -who",
	}

	for _, item := range required {
		if !strings.Contains(usage, item) {
			t.Fatalf("usage missing %q:\n%s", item, usage)
		}
	}
}

func TestOfflineUsageListsInputDirectory(t *testing.T) {
	usage := offlineUsageString("paasau")
	if !strings.Contains(usage, "Usage: paasau -offline [flags] <pcap-dir>") {
		t.Fatalf("unexpected usage:\n%s", usage)
	}
	if !strings.Contains(usage, "-foreign") {
		t.Fatalf("missing foreign compatibility flag:\n%s", usage)
	}
	if !strings.Contains(usage, "paasau -offline ./pcap_dump") {
		t.Fatalf("missing example:\n%s", usage)
	}
}

func TestResolvePolicyNameKeepsCompatibilityForeignSwitch(t *testing.T) {
	if got := resolvePolicyName("", true); got != "foreign-car" {
		t.Fatalf("expected foreign-car, got %q", got)
	}
	if got := resolvePolicyName("china-car", true); got != "china-car" {
		t.Fatalf("explicit policy should win, got %q", got)
	}
}

func TestRootUsageUsesHyphenModeNames(t *testing.T) {
	usage := rootUsageStringForMode("paasau", true)
	required := []string{
		"Usage: paasau [mode] [flags]",
		"-live      Capture live traffic and detect policy violations",
		"-offline   Scan pcap files in a directory",
	}
	for _, item := range required {
		if !strings.Contains(usage, item) {
			t.Fatalf("usage missing %q:\n%s", item, usage)
		}
	}
}
