package main

import (
	"log"
	"net"
	"strings"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Geographic routing functions

// newGeoResolver creates a new GeoIP resolver from configuration.
func newGeoResolver(c *GeoIPConfig) *geoResolver {
	if c == nil || !c.Enabled || c.Database == "" {
		return nil
	}
	db, err := maxminddb.Open(c.Database)
	if err != nil {
		log.Printf("geoip: open %s failed: %v", c.Database, err)
		return nil
	}
	ttl := time.Duration(600) * time.Second
	if c.CacheTTLSec > 0 {
		ttl = time.Duration(c.CacheTTLSec) * time.Second
	}
	preferRegistered := true
	if strings.ToLower(strings.TrimSpace(c.PreferField)) == "country" {
		preferRegistered = false
	}
	return &geoResolver{db: db, preferRegistered: preferRegistered, cache: make(map[string]geoCacheEntry), ttl: ttl}
}

// Close closes the GeoIP database.
func (g *geoResolver) Close() {
	if g == nil || g.db == nil {
		return
	}
	_ = g.db.Close()
}

// lookup performs a GeoIP lookup for an IP address.
func (g *geoResolver) lookup(ip net.IP) (country, continent string, ok bool) {
	if g == nil || g.db == nil || ip == nil {
		return "", "", false
	}
	key := ip.String()
	now := time.Now()
	g.mu.RLock()
	if e, ok := g.cache[key]; ok && now.Before(e.exp) {
		g.mu.RUnlock()
		return e.country, e.continent, true
	}
	g.mu.RUnlock()
	var rec mmdbCountry
	if err := g.db.Lookup(ip, &rec); err != nil {
		return "", "", false
	}
	cc := rec.Country.ISOCode
	if g.preferRegistered && rec.RegisteredCountry.ISOCode != "" {
		cc = rec.RegisteredCountry.ISOCode
	}
	cont := rec.Continent.Code
	g.mu.Lock()
	g.cache[key] = geoCacheEntry{country: strings.ToUpper(cc), continent: strings.ToUpper(cont), exp: now.Add(g.ttl)}
	g.mu.Unlock()
	return strings.ToUpper(cc), strings.ToUpper(cont), true
}

// pickTierByGeo selects a tier based on geographic policy.


// policyAllows checks if a tier is allowed for a given country/continent.


// answersByGeo provides geographic answer overrides.


