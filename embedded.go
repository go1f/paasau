package paasau

import "embed"

const (
	DefaultConfigPath       = "configs/default.json"
	DefaultLiveGeoIPDBPath  = "assets/mmdb/GeoIP2-CN-20260307.mmdb"
	DefaultOfflineGeoIPPath = "assets/mmdb/GeoLite2-City-250626-V01.mmdb"
)

//go:embed configs/default.json assets/mmdb/GeoIP2-CN-20260307.mmdb assets/mmdb/GeoLite2-City-250626-V01.mmdb
var embeddedFiles embed.FS

func DefaultConfig() ([]byte, error) {
	return embeddedFiles.ReadFile(DefaultConfigPath)
}

func DefaultLiveGeoIPDB() ([]byte, error) {
	return embeddedFiles.ReadFile(DefaultLiveGeoIPDBPath)
}

func DefaultOfflineGeoIPDB() ([]byte, error) {
	return embeddedFiles.ReadFile(DefaultOfflineGeoIPPath)
}
