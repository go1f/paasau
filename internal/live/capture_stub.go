//go:build !windows && !cgo
// +build !windows,!cgo

package live

import (
	"context"
	"fmt"
)

func (r *runner) captureInterface(context.Context, string, string, string) error {
	return fmt.Errorf("live capture requires cgo/libpcap support")
}
