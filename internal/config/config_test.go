package config

import "testing"

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
