package main

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// newGeoResolver constructs a GeoIP resolver with TTL cache.
// Returns nil if cfg is nil or disabled.
func newGeoResolver(cfg *GeoIPConfig) (*geoResolver, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if cfg.Database == "" {
		return nil, nil
	}
	db, err := maxminddb.Open(cfg.Database)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(cfg.CacheTTLSec) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	preferRegistered := true
	switch strings.ToLower(strings.TrimSpace(cfg.PreferField)) {
	case "country":
		preferRegistered = false
	default:
		preferRegistered = true
	}
	g := &geoResolver{
		db:               db,
		preferRegistered: preferRegistered,
		cache:            make(map[string]geoCacheEntry),
		ttl:              ttl,
	}
	return g, nil
}

// Close releases the MMDB handle.
func (g *geoResolver) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

// LabelsFor returns ISO country code and 2-letter continent code for an IP.
// Returns empty strings when not available or resolver disabled.
func (g *geoResolver) LabelsFor(ip net.IP) (country, continent string) {
	if g == nil || g.db == nil || ip == nil {
		return "", ""
	}
	key := ip.String()
	now := time.Now()
	g.mu.RLock()
	if e, ok := g.cache[key]; ok && now.Before(e.exp) {
		g.mu.RUnlock()
		return e.country, e.continent
	}
	g.mu.RUnlock()

	var rec mmdbCountry
	if err := g.db.Lookup(ip, &rec); err != nil {
		return "", ""
	}
	cnt := strings.ToUpper(rec.Continent.Code)
	var ctry string
	if g.preferRegistered {
		ctry = strings.ToUpper(rec.RegisteredCountry.ISOCode)
	} else {
		ctry = strings.ToUpper(rec.Country.ISOCode)
	}
	g.mu.Lock()
	g.cache[key] = geoCacheEntry{country: ctry, continent: cnt, exp: now.Add(g.ttl)}
	g.mu.Unlock()
	return ctry, cnt
}

// ecsClientIP tries to extract an ECS client IP from the OPT record.
// Returns nil if not present or malformed.
func ecsClientIP(msg *dns.Msg) net.IP {
	if msg == nil {
		return nil
	}
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, o := range opt.Option {
				if s, ok := o.(*dns.EDNS0_SUBNET); ok {
					if s.Address != nil && (s.Family == 1 || s.Family == 2) {
						return s.Address
					}
				}
			}
		}
	}
	return nil
}

// allowedByTier evaluates whether a geo tier policy permits the (country, continent).
// Country/continent matching is case-insensitive. If AllowAll is true, it passes.
func allowedByTier(pol GeoTierPolicy, country, continent string) bool {
	if pol.AllowAll {
		return true
	}
	country = strings.ToUpper(country)
	continent = strings.ToUpper(continent)
	if len(pol.AllowCountries) > 0 {
		for _, c := range pol.AllowCountries {
			if strings.ToUpper(strings.TrimSpace(c)) == country {
				return true
			}
		}
	}
	if len(pol.AllowContinents) > 0 {
		for _, c := range pol.AllowContinents {
			if strings.ToUpper(strings.TrimSpace(c)) == continent {
				return true
			}
		}
	}
	return false
}
