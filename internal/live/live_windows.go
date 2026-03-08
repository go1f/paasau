//go:build windows
// +build windows

package live

import (
	"context"
	"fmt"

	"paasau/internal/config"
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

func Run(ctx context.Context, cfg *config.Config, opts Options) error {
	_ = ctx
	_ = cfg
	_ = opts
	return fmt.Errorf("live capture is not supported in Windows builds; use the offline subcommand instead")
}
