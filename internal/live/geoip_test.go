//go:build !windows
// +build !windows

package live

import (
	"strings"
	"testing"
)

func TestOpenLiveGeoIPDBUsesEmbeddedDefault(t *testing.T) {
	reader, name, err := openLiveGeoIPDB("", "")
	if err != nil {
		t.Fatalf("openLiveGeoIPDB() error = %v", err)
	}
	defer reader.Close()

	if !strings.HasPrefix(name, "embedded:") {
		t.Fatalf("db name = %q, want embedded resource", name)
	}
}

func TestOpenLiveGeoIPDBPrefersOverride(t *testing.T) {
	const missing = "/definitely/missing/live.mmdb"
	_, name, err := openLiveGeoIPDB(missing, "")
	if err == nil {
		t.Fatal("expected error for missing override db")
	}
	if name != missing {
		t.Fatalf("db name = %q, want override %q", name, missing)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error %q does not mention override path", err.Error())
	}
}
