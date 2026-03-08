package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Runtime  RuntimeConfig     `json:"runtime"`
	Live     LiveConfig        `json:"live"`
	Offline  OfflineConfig     `json:"offline"`
	Policies map[string]Policy `json:"policies"`
}

type RuntimeConfig struct {
	Debug    bool   `json:"debug"`
	OutputDir string `json:"output_dir"`
	TimeZone string `json:"time_zone"`
}

type LiveConfig struct {
	DefaultPolicy               string `json:"default_policy"`
	GeoIPDB                     string `json:"geoip_db"`
	BPFFilter                   string `json:"bpf_filter"`
	WorkerLimit                 int    `json:"worker_limit"`
	ProcessLookupTimeoutSeconds int    `json:"process_lookup_timeout_seconds"`
	SnapLen                     int32  `json:"snaplen"`
	Promisc                     bool   `json:"promisc"`
	SavePcap                    bool   `json:"save_pcap"`
	FindProcess                 bool   `json:"find_process"`
}

type OfflineConfig struct {
	DefaultPolicy string `json:"default_policy"`
	GeoIPDB       string `json:"geoip_db"`
}

type Policy struct {
	Description string   `json:"description"`
	Mode        string   `json:"mode"`
	Countries   []string `json:"countries"`
}

func Load(path string) (*Config, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(bytes, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.applyDefaults()
	cfg.resolveRelativePaths(path)

	if len(cfg.Policies) == 0 {
		return nil, fmt.Errorf("config %s: policies must not be empty", path)
	}

	return &cfg, nil
}

func (c *Config) Policy(name string, fallback string) (string, Policy, error) {
	chosen := strings.TrimSpace(name)
	if chosen == "" {
		chosen = strings.TrimSpace(fallback)
	}
	policy, ok := c.Policies[chosen]
	if !ok {
		return "", Policy{}, fmt.Errorf("policy %q not found in config", chosen)
	}
	return chosen, normalizePolicy(policy), nil
}

func normalizePolicy(policy Policy) Policy {
	out := policy
	out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	if out.Mode == "" {
		out.Mode = "allowlist"
	}
	for i, code := range out.Countries {
		out.Countries[i] = strings.ToUpper(strings.TrimSpace(code))
	}
	return out
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Runtime.OutputDir) == "" {
		c.Runtime.OutputDir = "runtime/output"
	}
	if strings.TrimSpace(c.Runtime.TimeZone) == "" {
		c.Runtime.TimeZone = "Asia/Shanghai"
	}
	if c.Live.WorkerLimit <= 0 {
		c.Live.WorkerLimit = 2
	}
	if c.Live.ProcessLookupTimeoutSeconds <= 0 {
		c.Live.ProcessLookupTimeoutSeconds = 5
	}
	if c.Live.SnapLen <= 0 {
		c.Live.SnapLen = 65536
	}
	if strings.TrimSpace(c.Live.BPFFilter) == "" {
		c.Live.BPFFilter = "ip"
	}
	if strings.TrimSpace(c.Live.DefaultPolicy) == "" {
		c.Live.DefaultPolicy = "china-car"
	}
	if strings.TrimSpace(c.Offline.DefaultPolicy) == "" {
		c.Offline.DefaultPolicy = "china-car"
	}
}

func (c *Config) resolveRelativePaths(configPath string) {
	baseDir := filepath.Dir(configPath)
	c.Runtime.OutputDir = resolvePath(baseDir, c.Runtime.OutputDir)
	c.Live.GeoIPDB = resolvePath(baseDir, c.Live.GeoIPDB)
	c.Offline.GeoIPDB = resolvePath(baseDir, c.Offline.GeoIPDB)
}

func resolvePath(baseDir string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}
