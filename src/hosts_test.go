package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

func TestHostPoolAnswers(t *testing.T) {
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
		Lightup: &LightupConfig{
			Enabled:         true,
			TTL:             60,
			Forward:         true,
			ForwardTemplate: "templated-{addr}.example.org.",
			Families: []LightupFamily{{
				Family:      "ipv6",
				Class:       "public",
				Prefix:      "2001:db8:ffff::/64",
				RespondAAAA: true,
			}},
		},
		Hosts: []Host{{
			Name: "app",
			Pools: []Pool{
				{Name: "eu-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2001:db8:1::10"}}},
				{Name: "us-v6", Family: "ipv6", Class: "public", Role: "secondary", Members: []IPAddr{{IP: "2001:db8:2::10"}}},
				{Name: "eu-v4", Family: "ipv4", Class: "public", Role: "primary", Members: []IPAddr{{IP: "198.51.100.10"}}},
				{Name: "us-v4", Family: "ipv4", Class: "public", Role: "secondary", Members: []IPAddr{{IP: "198.51.100.20"}}},
			},
			Geo: &GeoPolicy{Named: []NamedGeoPolicy{
				{Name: "eu-v6", Policy: GeoTierPolicy{AllowCountries: []string{"GB"}, AllowContinents: []string{"EU"}}},
				{Name: "eu-v4", Policy: GeoTierPolicy{AllowCountries: []string{"GB"}, AllowContinents: []string{"EU"}}},
				{Name: "us-v6", Policy: GeoTierPolicy{AllowCountries: []string{"US"}, AllowContinents: []string{"NA"}}},
				{Name: "us-v4", Policy: GeoTierPolicy{AllowCountries: []string{"US"}, AllowContinents: []string{"NA"}}},
			}},
		}},
	}}}
	config.SetupDefaults(cfg)

	gr := &geoResolver{
		db: &maxminddb.Reader{},
		cache: map[string]geoCacheEntry{
			"203.0.113.10":  {country: "GB", continent: "EU", exp: time.Now().Add(time.Hour)},
			"198.51.100.10": {country: "US", continent: "NA", exp: time.Now().Add(time.Hour)},
		},
		ttl: time.Hour,
	}
	_, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.state.mu.Lock()
	auth.state.standby.v4.up = true
	auth.state.standby.v6.up = true
	auth.state.mu.Unlock()
	hostState := auth.serviceState("app.example.org.")
	hostState.mu.Lock()
	hostState.master.v4.up = true
	hostState.master.v6.up = true
	hostState.standby.v4.up = true
	hostState.standby.v6.up = true
	hostState.mu.Unlock()

	if !auth.zidx.hasName("app.example.org.") {
		t.Fatalf("expected host name in zone index")
	}
	if got := auth.addrAAAA("app.example.org.", net.ParseIP("203.0.113.10"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:1::10" {
		t.Fatalf("GB AAAA should use host eu-v6 pool, got %v", got)
	}
	if got := auth.addrA("app.example.org.", net.ParseIP("198.51.100.10"), nil); len(got) != 1 || got[0].(*dns.A).A.String() != "198.51.100.20" {
		t.Fatalf("US A should use host us-v4 pool, got %v", got)
	}
	if got := auth.addrAAAA("app.example.org.", net.ParseIP("2001:db8::1"), nil); len(got) != 1 || got[0].(*dns.AAAA).AAAA.String() != "2001:db8:1::10" {
		t.Fatalf("explicit host should win before lightup synthesis, got %v", got)
	}
}

func TestApexHostPoolsAnswerAtApex(t *testing.T) {
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
		Hosts: []Host{{
			Name: "@",
			Pools: []Pool{
				{Name: "apex-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2001:db8:40::10"}}},
				{Name: "apex-v4", Family: "ipv4", Class: "public", Role: "primary", Members: []IPAddr{{IP: "198.51.100.40"}}},
			},
		}},
	}}}
	config.SetupDefaults(cfg)
	_, auth := startRecordServer(t, cfg, nil)
	auth.setMasterUp(true, true)
	hostState := auth.serviceState("example.org.")
	hostState.mu.Lock()
	hostState.master.v4.up = true
	hostState.master.v6.up = true
	hostState.mu.Unlock()

	gotAAAA := auth.addrAAAA("example.org.", net.ParseIP("2001:db8::10"), nil)
	if len(gotAAAA) != 1 || gotAAAA[0].(*dns.AAAA).AAAA.String() != "2001:db8:40::10" {
		t.Fatalf("expected apex host AAAA answer, got %v", gotAAAA)
	}
	gotA := auth.addrA("example.org.", net.ParseIP("198.51.100.10"), nil)
	if len(gotA) != 1 || gotA[0].(*dns.A).A.String() != "198.51.100.40" {
		t.Fatalf("expected apex host A answer, got %v", gotA)
	}
}

func TestHostPoolRecordsReplicateToSecondary(t *testing.T) {
	ensureIPv4(t)
	mcfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		Refresh:   1,
		Retry:     1,
		Expire:    60,
		Hosts: []Host{{
			Name: "app",
			Pools: []Pool{
				{Name: "app-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2001:db8::10"}}},
				{Name: "app-v4", Family: "ipv4", Class: "public", Role: "primary", Members: []IPAddr{{IP: "192.0.2.10"}}},
			},
		}},
	}}}
	config.SetupDefaults(mcfg)
	mcfg.TimeoutSec = 0
	_, maddr, mAuth := startTestServer(t, mcfg, nil, nil)
	mAuth.cancel()

	scfg := &Config{Zones: []Zone{{
		Name:  "example.org.",
		Serve: "secondary",
	}}}
	config.SetupDefaults(scfg)
	scfg.TimeoutSec = 0
	saddr, sauth := startRecordServer(t, scfg, nil)
	sauth.cancel()
	sauth.zone.Masters = []string{maddr}
	if err := sauth.transferFromMasters(); err != nil {
		t.Fatalf("initial transfer: %v", err)
	}

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("app.example.org.", dns.TypeAAAA)
	r, _, err := c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("query secondary app AAAA: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::10" {
		t.Fatalf("unexpected app AAAA answer from secondary: %v", r.Answer)
	}
	m.SetQuestion("app.example.org.", dns.TypeA)
	r, _, err = c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("query secondary app A: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.10" {
		t.Fatalf("unexpected app A answer from secondary: %v", r.Answer)
	}
}

func TestHostHealthOverrideBeatsZoneDefault(t *testing.T) {
	ensureIPv6(t)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("listen tcp6: %v", err)
	}
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Shutdown(context.Background())
	port := ln.Addr().(*net.TCPAddr).Port

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
			{Name: "apex-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2001:db8::dead"}}},
		},
		Health: &HealthConfig{
			Kind:   "http",
			Scheme: "http",
			Path:   "/unhealthy",
			Port:   port,
			Expect: "OK",
		},
		Hosts: []Host{{
			Name: "app",
			Pools: []Pool{
				{Name: "app-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "::1"}}},
			},
			Health: &HealthConfig{
				Kind:       "http",
				Scheme:     "http",
				Path:       "/health",
				Port:       port,
				Expect:     "OK",
				HostHeader: "app.example.org",
			},
		}},
	}}}
	config.SetupDefaults(cfg)
	cfg.TimeoutSec = 1
	cfg.Rise = 1
	cfg.Fall = 1
	_, auth := startRecordServer(t, cfg, nil)
	auth.checkOnce()

	if got := auth.addrAAAA("example.org.", net.ParseIP("2001:db8::10"), nil); len(got) != 0 {
		t.Fatalf("expected apex AAAA to stay down under zone default health, got %v", got)
	}
	got := auth.addrAAAA("app.example.org.", net.ParseIP("2001:db8::10"), nil)
	if len(got) != 1 {
		t.Fatalf("expected host AAAA answer under host override health, got %v", got)
	}
	if got[0].(*dns.AAAA).AAAA.String() != "::1" {
		t.Fatalf("unexpected host AAAA answer: %v", got)
	}
	if !tierUpState(auth.serviceState("app.example.org."), "master", true) {
		t.Fatalf("expected host-specific master v6 state to be up")
	}
	if tierUpState(auth.state, "master", true) {
		t.Fatalf("expected zone master v6 state to remain down")
	}
}
