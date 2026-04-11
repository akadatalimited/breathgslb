package main

import (
	"net"
	"testing"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

func TestNamedPoolGeoSelectionAtApex(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    300,
		TTLAnswer: 60,
		Refresh:   300,
		Retry:     60,
		Expire:    3600,
		Minttl:    60,
		Pools: []Pool{
			{Name: "eu-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2001:db8:1::1"}}},
			{Name: "us-v6", Family: "ipv6", Class: "public", Role: "secondary", Members: []IPAddr{{IP: "2001:db8:2::1"}}},
			{Name: "global-v6", Family: "ipv6", Class: "public", Role: "fallback", Members: []IPAddr{{IP: "2001:db8:3::1"}}},
			{Name: "eu-v4", Family: "ipv4", Class: "public", Role: "primary", Members: []IPAddr{{IP: "198.51.100.1"}}},
			{Name: "us-v4", Family: "ipv4", Class: "public", Role: "secondary", Members: []IPAddr{{IP: "198.51.100.2"}}},
			{Name: "global-v4", Family: "ipv4", Class: "public", Role: "fallback", Members: []IPAddr{{IP: "198.51.100.3"}}},
		},
		Geo: &GeoPolicy{
			Named: []NamedGeoPolicy{
				{Name: "eu-v6", Policy: GeoTierPolicy{AllowCountries: []string{"GB", "FR", "DE"}, AllowContinents: []string{"EU"}}},
				{Name: "eu-v4", Policy: GeoTierPolicy{AllowCountries: []string{"GB", "FR", "DE"}, AllowContinents: []string{"EU"}}},
				{Name: "us-v6", Policy: GeoTierPolicy{AllowCountries: []string{"US", "CA"}, AllowContinents: []string{"NA"}}},
				{Name: "us-v4", Policy: GeoTierPolicy{AllowCountries: []string{"US", "CA"}, AllowContinents: []string{"NA"}}},
				{Name: "global-v6", Policy: GeoTierPolicy{AllowAll: true}},
				{Name: "global-v4", Policy: GeoTierPolicy{AllowAll: true}},
			},
		},
	}}}
	config.SetupDefaults(cfg)

	gr := &geoResolver{
		db: &maxminddb.Reader{},
		cache: map[string]geoCacheEntry{
			"203.0.113.10":  {country: "GB", continent: "EU", exp: time.Now().Add(time.Hour)},
			"198.51.100.10": {country: "US", continent: "NA", exp: time.Now().Add(time.Hour)},
			"192.0.2.10":    {country: "AU", continent: "OC", exp: time.Now().Add(time.Hour)},
		},
		ttl: time.Hour,
	}
	_, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.state.mu.Lock()
	auth.state.standby.v4.up = true
	auth.state.standby.v6.up = true
	auth.state.mu.Unlock()

	zone := cfg.Zones[0].Name
	if got := auth.addrAAAA(zone, net.ParseIP("203.0.113.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:1::1" {
		t.Fatalf("GB AAAA should use eu-v6, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("203.0.113.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.1" {
		t.Fatalf("GB A should use eu-v4, got %v", got)
	}
	if got := auth.addrAAAA(zone, net.ParseIP("198.51.100.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:2::1" {
		t.Fatalf("US AAAA should use us-v6, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("198.51.100.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.2" {
		t.Fatalf("US A should use us-v4, got %v", got)
	}
	if got := auth.addrAAAA(zone, net.ParseIP("192.0.2.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:3::1" {
		t.Fatalf("AU AAAA should use global-v6, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("192.0.2.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.3" {
		t.Fatalf("AU A should use global-v4, got %v", got)
	}
}

func TestApexPoolFallbackAcrossRoles(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    300,
		TTLAnswer: 60,
		Refresh:   300,
		Retry:     60,
		Expire:    3600,
		Minttl:    60,
		Pools: []Pool{
			{Name: "primary-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2001:db8:1::1"}}},
			{Name: "secondary-v6", Family: "ipv6", Class: "public", Role: "secondary", Members: []IPAddr{{IP: "2001:db8:2::1"}}},
			{Name: "fallback-v6", Family: "ipv6", Class: "public", Role: "fallback", Members: []IPAddr{{IP: "2001:db8:3::1"}}},
		},
	}}}
	config.SetupDefaults(cfg)

	_, auth := startRecordServer(t, cfg, nil)
	auth.setMasterUp(false, false)
	auth.state.mu.Lock()
	auth.state.standby.v4.up = true
	auth.state.standby.v6.up = true
	auth.state.mu.Unlock()

	if got := auth.addrAAAA(cfg.Zones[0].Name, net.ParseIP("2001:db8::10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:2::1" {
		t.Fatalf("expected secondary-v6 fallback when primary is down, got %v", got)
	}

	auth.state.mu.Lock()
	auth.state.standby.v6.up = false
	auth.state.mu.Unlock()
	if got := auth.addrAAAA(cfg.Zones[0].Name, net.ParseIP("2001:db8::10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:3::1" {
		t.Fatalf("expected fallback-v6 when primary and secondary are down, got %v", got)
	}
}
