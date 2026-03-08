//go:build !windows
// +build !windows

package live

import (
	"testing"
	"time"
)

func TestSaveWindowTrigger(t *testing.T) {
	window := newSaveWindow(50 * time.Millisecond)
	now := time.Now()

	if window.Active(now) {
		t.Fatal("window should be inactive before trigger")
	}
	window.Trigger(now)
	if !window.Active(now.Add(10 * time.Millisecond)) {
		t.Fatal("window should be active after trigger")
	}
	if window.Active(now.Add(60 * time.Millisecond)) {
		t.Fatal("window should expire")
	}
}

func TestSaveWindowContinuousWhenDisabled(t *testing.T) {
	window := newSaveWindow(0)
	if !window.Active(time.Now()) {
		t.Fatal("zero-duration window should be always active")
	}
}
