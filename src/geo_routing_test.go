package main

import (
	"net"
	"testing"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

func geoTestResolver(entries map[string]geoCacheEntry) *geoResolver {
	return &geoResolver{
		db:    &maxminddb.Reader{},
		cache: entries,
		ttl:   time.Hour,
	}
}

func TestGeoPolicySteersApexAnswers(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:         "example.org.",
		NS:           []string{"ns.example.org."},
		Admin:        "hostmaster.example.org.",
		TTLSOA:       300,
		TTLAnswer:    60,
		Refresh:      300,
		Retry:        60,
		Expire:       3600,
		Minttl:       60,
		AAAAMaster:   []IPAddr{{IP: "2001:db8:1::1"}},
		AAAAStandby:  []IPAddr{{IP: "2001:db8:2::1"}},
		AAAAFallback: []IPAddr{{IP: "2001:db8:3::1"}},
		AMaster:      []IPAddr{{IP: "198.51.100.1"}},
		AStandby:     []IPAddr{{IP: "198.51.100.2"}},
		AFallback:    []IPAddr{{IP: "198.51.100.3"}},
		Geo: &GeoPolicy{
			Master: GeoTierPolicy{
				AllowCountries:  []string{"GB"},
				AllowContinents: []string{"EU"},
			},
			Standby: GeoTierPolicy{
				AllowCountries: []string{"US", "CA"},
			},
			Fallback: GeoTierPolicy{
				AllowAll: true,
			},
		},
	}}}
	config.SetupDefaults(cfg)

	gr := geoTestResolver(map[string]geoCacheEntry{
		"203.0.113.10":  {country: "GB", continent: "EU", exp: time.Now().Add(time.Hour)},
		"198.51.100.10": {country: "US", continent: "NA", exp: time.Now().Add(time.Hour)},
		"192.0.2.10":    {country: "AU", continent: "OC", exp: time.Now().Add(time.Hour)},
	})
	_, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.state.mu.Lock()
	auth.state.standby.v4.up = true
	auth.state.standby.v6.up = true
	auth.state.mu.Unlock()

	zone := cfg.Zones[0].Name

	if got := auth.addrAAAA(zone, net.ParseIP("203.0.113.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:1::1" {
		t.Fatalf("GB AAAA should steer to master, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("203.0.113.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.1" {
		t.Fatalf("GB A should steer to master, got %v", got)
	}
	if got := auth.addrAAAA(zone, net.ParseIP("198.51.100.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:2::1" {
		t.Fatalf("US AAAA should steer to standby, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("198.51.100.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.2" {
		t.Fatalf("US A should steer to standby, got %v", got)
	}
	if got := auth.addrAAAA(zone, net.ParseIP("192.0.2.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:3::1" {
		t.Fatalf("AU AAAA should steer to fallback, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("192.0.2.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.3" {
		t.Fatalf("AU A should steer to fallback, got %v", got)
	}
}

func TestGeoAnswersOverrideApexAnswers(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:         "example.org.",
		NS:           []string{"ns.example.org."},
		Admin:        "hostmaster.example.org.",
		TTLSOA:       300,
		TTLAnswer:    60,
		Refresh:      300,
		Retry:        60,
		Expire:       3600,
		Minttl:       60,
		AAAAMaster:   []IPAddr{{IP: "2001:db8:1::1"}},
		AAAAStandby:  []IPAddr{{IP: "2001:db8:2::1"}},
		AAAAFallback: []IPAddr{{IP: "2001:db8:3::1"}},
		AMaster:      []IPAddr{{IP: "198.51.100.1"}},
		AStandby:     []IPAddr{{IP: "198.51.100.2"}},
		AFallback:    []IPAddr{{IP: "198.51.100.3"}},
		GeoAnswers: &GeoAnswers{
			Country: map[string]GeoAnswerSet{
				"GB": {
					AAAA: []string{"2001:db8:beef::1"},
					A:    []string{"198.51.100.200"},
				},
			},
			Continent: map[string]GeoAnswerSet{
				"EU": {
					AAAA: []string{"2001:db8:face::1"},
					A:    []string{"198.51.100.201"},
				},
			},
		},
	}}}
	config.SetupDefaults(cfg)

	gr := geoTestResolver(map[string]geoCacheEntry{
		"203.0.113.10": {country: "GB", continent: "EU", exp: time.Now().Add(time.Hour)},
		"203.0.113.11": {country: "FR", continent: "EU", exp: time.Now().Add(time.Hour)},
	})
	_, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)

	zone := cfg.Zones[0].Name

	if got := auth.addrAAAA(zone, net.ParseIP("203.0.113.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:beef::1" {
		t.Fatalf("GB AAAA should use country override, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("203.0.113.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.200" {
		t.Fatalf("GB A should use country override, got %v", got)
	}
	if got := auth.addrAAAA(zone, net.ParseIP("203.0.113.11"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:face::1" {
		t.Fatalf("FR AAAA should use continent override, got %v", got)
	}
	if got := auth.addrA(zone, net.ParseIP("203.0.113.11"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.201" {
		t.Fatalf("FR A should use continent override, got %v", got)
	}
}
