//go:build !windows
// +build !windows

package live

import "time"

type saveWindow struct {
	duration    time.Duration
	activeUntil time.Time
}

func newSaveWindow(duration time.Duration) *saveWindow {
	return &saveWindow{duration: duration}
}

func (w *saveWindow) Trigger(now time.Time) {
	if w.duration <= 0 {
		return
	}
	w.activeUntil = now.Add(w.duration)
}

func (w *saveWindow) Active(now time.Time) bool {
	if w.duration <= 0 {
		return true
	}
	return now.Before(w.activeUntil)
}
