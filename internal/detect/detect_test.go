package detect

import (
	"net"
	"testing"

	"paasau/internal/config"
)

func TestPrivateIPAlwaysAllowed(t *testing.T) {
	detector := &Detector{
		policy: config.Policy{Mode: "allowlist", Countries: []string{"CN"}},
		codes:  map[string]struct{}{"CN": {}},
	}

	result, err := detector.Evaluate(net.ParseIP("192.168.1.2"))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result.Allowed {
		t.Fatalf("private IP should be allowed, got %+v", result)
	}
}

func TestAllowlistPolicy(t *testing.T) {
	detector := &Detector{
		policy: config.Policy{Mode: "allowlist", Countries: []string{"CN"}},
		codes:  map[string]struct{}{"CN": {}},
	}
	detector.cache.Store("8.8.8.8", "US")

	result, err := detector.Evaluate(net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result.Allowed {
		t.Fatalf("US should be blocked in CN allowlist, got %+v", result)
	}
}

func TestDenylistPolicy(t *testing.T) {
	detector := &Detector{
		policy: config.Policy{Mode: "denylist", Countries: []string{"CN"}},
		codes:  map[string]struct{}{"CN": {}},
	}
	detector.cache.Store("1.1.1.1", "US")
	detector.cache.Store("114.114.114.114", "CN")

	allowed, err := detector.Evaluate(net.ParseIP("1.1.1.1"))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("US should be allowed in CN denylist, got %+v", allowed)
	}

	blocked, err := detector.Evaluate(net.ParseIP("114.114.114.114"))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if blocked.Allowed {
		t.Fatalf("CN should be blocked in CN denylist, got %+v", blocked)
	}
}
