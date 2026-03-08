package cache

import (
	"testing"
	"time"
)

func TestTTLCacheEvictsLeastRecent(t *testing.T) {
	cache := NewTTLCache(2, time.Minute)
	cache.Add("a", "1")
	cache.Add("b", "2")
	if _, ok := cache.Get("a"); !ok {
		t.Fatal("expected a to exist")
	}
	cache.Add("c", "3")

	if _, ok := cache.Get("b"); ok {
		t.Fatal("expected b to be evicted")
	}
	if value, ok := cache.Get("a"); !ok || value != "1" {
		t.Fatalf("expected a to stay, got %q %v", value, ok)
	}
}

func TestTTLCacheExpires(t *testing.T) {
	cache := NewTTLCache(2, 10*time.Millisecond)
	cache.Add("a", "1")
	time.Sleep(20 * time.Millisecond)

	if _, ok := cache.Get("a"); ok {
		t.Fatal("expected a to expire")
	}
}
