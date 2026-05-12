package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultUsesEmbeddedConfig(t *testing.T) {
	cfg, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault() error = %v", err)
	}
	if cfg.Live.DefaultPolicy != "china-car" {
		t.Fatalf("unexpected live default policy: %q", cfg.Live.DefaultPolicy)
	}
	if cfg.Runtime.OutputDir != "runtime/output" {
		t.Fatalf("embedded default config should resolve output dir like configs/default.json, got %q", cfg.Runtime.OutputDir)
	}
	if cfg.Live.GeoIPDB != "" {
		t.Fatalf("embedded default config should use embedded live db, got %q", cfg.Live.GeoIPDB)
	}
	if cfg.Offline.GeoIPDB != "" {
		t.Fatalf("embedded default config should use embedded offline db, got %q", cfg.Offline.GeoIPDB)
	}
	if _, _, err := cfg.Policy("", cfg.Live.DefaultPolicy); err != nil {
		t.Fatalf("default policy not available: %v", err)
	}
}

func TestLoadExternalConfigResolvesPathsRelativeToConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nested", "default.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}

	configJSON := `{
  "runtime": {"output_dir": "out", "time_zone": "Asia/Shanghai"},
  "live": {"default_policy": "china-car", "geoip_db": "db/live.mmdb"},
  "offline": {"default_policy": "china-car", "geoip_db": "db/offline.mmdb"},
  "policies": {
    "china-car": {"mode": "allowlist", "countries": ["CN"]}
  }
}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	base := filepath.Dir(configPath)
	if cfg.Runtime.OutputDir != filepath.Join(base, "out") {
		t.Fatalf("output dir = %q, want %q", cfg.Runtime.OutputDir, filepath.Join(base, "out"))
	}
	if cfg.Live.GeoIPDB != filepath.Join(base, "db/live.mmdb") {
		t.Fatalf("live db = %q, want %q", cfg.Live.GeoIPDB, filepath.Join(base, "db/live.mmdb"))
	}
	if cfg.Offline.GeoIPDB != filepath.Join(base, "db/offline.mmdb") {
		t.Fatalf("offline db = %q, want %q", cfg.Offline.GeoIPDB, filepath.Join(base, "db/offline.mmdb"))
	}
}

func TestNormalizePolicyDefaults(t *testing.T) {
	policy := normalizePolicy(Policy{
		Countries: []string{" cn ", "us"},
	})

	if policy.Mode != "allowlist" {
		t.Fatalf("expected default mode allowlist, got %q", policy.Mode)
	}
	if policy.Countries[0] != "CN" || policy.Countries[1] != "US" {
		t.Fatalf("countries not normalized: %+v", policy.Countries)
	}
}
