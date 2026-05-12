package offline

import (
	"strings"
	"testing"
)

func TestOpenOfflineGeoIPDBUsesEmbeddedDefault(t *testing.T) {
	reader, name, err := openOfflineGeoIPDB("", "")
	if err != nil {
		t.Fatalf("openOfflineGeoIPDB() error = %v", err)
	}
	defer reader.Close()

	if !strings.HasPrefix(name, "embedded:") {
		t.Fatalf("db name = %q, want embedded resource", name)
	}
}

func TestOpenOfflineGeoIPDBPrefersOverride(t *testing.T) {
	const missing = "/definitely/missing/offline.mmdb"
	_, name, err := openOfflineGeoIPDB(missing, "")
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

func TestOpenOfflineGeoIPDBPrefersConfiguredExternalPath(t *testing.T) {
	const missing = "/definitely/missing/configured-offline.mmdb"
	_, name, err := openOfflineGeoIPDB("", missing)
	if err == nil {
		t.Fatal("expected error for missing configured db")
	}
	if name != missing {
		t.Fatalf("db name = %q, want configured path %q", name, missing)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error %q does not mention configured path", err.Error())
	}
}
