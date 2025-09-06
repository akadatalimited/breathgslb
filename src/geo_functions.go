package main

import (
	"net"
	"strings"
	"sync"
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
func (a *authority) pickTierByGeo(src net.IP, ipv6 bool) string {
	if a.geo == nil || a.zone.Geo == nil || src == nil {
		return ""
	}
	cc, cont, ok := a.geo.lookup(src)
	if !ok {
		return ""
	}
	// Check in order: master -> standby -> fallback, but only if policy allows
	check := func(tier string, famV6 bool) bool {
		if !a.policyAllows(tier, cc, cont) {
			return false
		}
		// also require health for master/standby
		if tier == "fallback" {
			return true
		}
		return a.tierUp(tier, famV6)
	}
	if check("master", ipv6) {
		return "master"
	}
	if check("standby", ipv6) {
		return "standby"
	}
	if a.policyAllows("fallback", cc, cont) {
		return "fallback"
	}
	return ""
}

// policyAllows checks if a tier is allowed for a given country/continent.
func (a *authority) policyAllows(tier string, country, continent string) bool {
	g := a.zone.Geo
	if g == nil {
		return false
	}
	var tp GeoTierPolicy
	switch tier {
	case "master":
		tp = g.Master
	case "standby":
		tp = g.Standby
	default:
		tp = g.Fallback
	}
	if tp.AllowAll {
		return true
	}
	country = strings.ToUpper(strings.TrimSpace(country))
	continent = strings.ToUpper(strings.TrimSpace(continent))
	contains := func(list []string, v string) bool {
		for _, x := range list {
			if strings.ToUpper(strings.TrimSpace(x)) == v {
				return true
			}
		}
		return false
	}
	if len(tp.AllowCountries) > 0 && contains(tp.AllowCountries, country) {
		return true
	}
	if len(tp.AllowContinents) > 0 && contains(tp.AllowContinents, continent) {
		return true
	}
	return false
}

// answersByGeo provides geographic answer overrides.
func (a *authority) answersByGeo(owner string, src net.IP, ipv6 bool) []dns.RR {
	if a.geo == nil || a.zone.GeoAnswers == nil || src == nil {
		return nil
	}
	cc, cont, ok := a.geo.lookup(src)
	if !ok {
		return nil
	}
	cc = strings.ToUpper(cc)
	cont = strings.ToUpper(cont)
	// Country has priority over continent
	if s, ok := a.zone.GeoAnswers.Country[cc]; ok {
		if a.isLocalGeo(cc, true, src) { // true => country
			if ipv6 && len(s.AAAAPrivate) > 0 {
				return a.buildAAAA(s.AAAAPrivate)
			}
			if !ipv6 && len(s.APrivate) > 0 {
				return a.buildA(s.APrivate)
			}
		}
		if ipv6 && len(s.AAAA) > 0 {
			return a.buildAAAA(s.AAAA)
		}
		if !ipv6 && len(s.A) > 0 {
			return a.buildA(s.A)
		}
	}
	if s, ok := a.zone.GeoAnswers.Continent[cont]; ok {
		if a.isLocalGeo(cont, false, src) { // false => continent
			if ipv6 && len(s.AAAAPrivate) > 0 {
				return a.buildAAAA(s.AAAAPrivate)
			}
			if !ipv6 && len(s.APrivate) > 0 {
				return a.buildA(s.APrivate)
			}
		}
		if ipv6 && len(s.AAAA) > 0 {
			return a.buildAAAA(s.AAAA)
		}
		if !ipv6 && len(s.A) > 0 {
			return a.buildA(s.A)
		}
	}
	return nil
}

// isLocalGeo checks if an IP is local for a geographic region.
func (a *authority) isLocalGeo(key string, isCountry bool, ip net.IP) bool {
	if isCountry {
		p, ok := a.geoCIDR.country[key]
		if !ok {
			return false
		}
		return inAnyCIDR(ip, p.rfc) || inAnyCIDR(ip, p.ula)
	}
	p, ok := a.geoCIDR.continent[key]
	if !ok {
		return false
	}
	return inAnyCIDR(ip, p.rfc) || inAnyCIDR(ip, p.ula)
}