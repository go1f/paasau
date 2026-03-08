package detect

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"paasau/internal/config"
	"paasau/internal/geoip"
)

type Result struct {
	IP      string
	Country string
	Allowed bool
	Reason  string
}

type Detector struct {
	reader  *geoip.Reader
	policy  config.Policy
	codes   map[string]struct{}
	cache   sync.Map
}

func New(reader *geoip.Reader, policy config.Policy) *Detector {
	codes := make(map[string]struct{}, len(policy.Countries))
	for _, code := range policy.Countries {
		codes[strings.ToUpper(code)] = struct{}{}
	}
	return &Detector{
		reader:  reader,
		policy:  policy,
		codes:   codes,
	}
}

func (d *Detector) Evaluate(ip net.IP) (Result, error) {
	if ip == nil {
		return Result{}, fmt.Errorf("nil ip")
	}

	if isPrivateOrReservedIP(ip) {
		return Result{
			IP:      ip.String(),
			Allowed: true,
			Reason:  "private_or_reserved",
		}, nil
	}

	country, err := d.countryCode(ip)
	if err != nil {
		return Result{}, err
	}

	_, exists := d.codes[country]
	allowed := exists
	if d.policy.Mode == "denylist" {
		allowed = !exists
	}
	reason := "country_blocked"
	if allowed {
		reason = "country_allowed"
	}

	return Result{
		IP:      ip.String(),
		Country: country,
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

func (d *Detector) countryCode(ip net.IP) (string, error) {
	if value, ok := d.cache.Load(ip.String()); ok {
		return value.(string), nil
	}

	country, err := d.reader.CountryCode(ip)
	if err != nil {
		return "", err
	}
	d.cache.Store(ip.String(), country)
	return country, nil
}

func isPrivateOrReservedIP(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() ||
		ip.String() == "255.255.255.255"
}
