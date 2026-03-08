package cache

import (
	"testing"
	"time"
)

func TestTTLSetCooldown(t *testing.T) {
	set := NewTTLSet(4, 20*time.Millisecond)
	if !set.Allow("ip1") {
		t.Fatal("first call should be allowed")
	}
	if set.Allow("ip1") {
		t.Fatal("second immediate call should be blocked")
	}
	time.Sleep(25 * time.Millisecond)
	if !set.Allow("ip1") {
		t.Fatal("call after ttl should be allowed")
	}
}
