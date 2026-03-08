package geoip

import (
	"fmt"
	"net"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

type Reader struct {
	reader *geoip2.Reader
}

func Open(path string) (*Reader, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip db %s: %w", path, err)
	}
	return &Reader{reader: reader}, nil
}

func (r *Reader) Close() error {
	return r.reader.Close()
}

func (r *Reader) CountryCode(ip net.IP) (string, error) {
	record, err := r.reader.Country(ip)
	if err != nil {
		return "", fmt.Errorf("lookup ip %s: %w", ip.String(), err)
	}
	return strings.ToUpper(record.Country.IsoCode), nil
}
