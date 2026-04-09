package main

import (
	"net"
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func startZonesServer(t *testing.T, cfg *Config) (string, map[string]*authority) {
	t.Helper()
	ensureIPv4(t)
	config.SetupDefaults(cfg)
	if err := config.GenerateReverseZones(cfg); err != nil {
		t.Fatalf("GenerateReverseZones: %v", err)
	}
	mux, auths := buildMux(cfg, nil, nil, nil)
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{Listener: l, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { srv.Shutdown() })
	for _, auth := range auths {
		a := auth
		t.Cleanup(a.cancel)
	}
	return l.Addr().String(), auths
}

func TestPTRPrimarySecondaryConsistency(t *testing.T) {
	ensureIPv4(t)
	primaryCfg := &Config{Zones: []Zone{
		{
			Name:      "example.org.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    3600,
			TTLAnswer: 300,
			Refresh:   1,
			Retry:     1,
			Expire:    60,
			Minttl:    60,
			AMaster:   []IPAddr{{IP: "192.0.2.1", Reverse: true}},
		},
		{
			Name:      "2.0.192.in-addr.arpa.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    3600,
			TTLAnswer: 300,
			Refresh:   1,
			Retry:     1,
			Expire:    60,
			Minttl:    60,
		},
	}}
	primaryAddr, _ := startZonesServer(t, primaryCfg)

	secondaryCfg := &Config{Zones: []Zone{{
		Name:    "2.0.192.in-addr.arpa.",
		Serve:   "secondary",
		Masters: []string{primaryAddr},
	}}}
	secondaryAddr, auths := startZonesServer(t, secondaryCfg)
	secondary := auths["2.0.192.in-addr.arpa."]
	if err := secondary.transferFromMasters(); err != nil {
		t.Fatalf("initial transfer: %v", err)
	}

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("1.2.0.192.in-addr.arpa.", dns.TypePTR)

	primaryResp, _, err := c.Exchange(m, primaryAddr)
	if err != nil {
		t.Fatalf("query primary: %v", err)
	}
	secondaryResp, _, err := c.Exchange(m, secondaryAddr)
	if err != nil {
		t.Fatalf("query secondary: %v", err)
	}
	if len(primaryResp.Answer) != 1 || len(secondaryResp.Answer) != 1 {
		t.Fatalf("unexpected PTR counts primary=%v secondary=%v", primaryResp.Answer, secondaryResp.Answer)
	}
	gotPrimary := primaryResp.Answer[0].(*dns.PTR).Ptr
	gotSecondary := secondaryResp.Answer[0].(*dns.PTR).Ptr
	if gotPrimary != "example.org." || gotSecondary != gotPrimary {
		t.Fatalf("PTR mismatch primary=%q secondary=%q", gotPrimary, gotSecondary)
	}
}

func TestRealPTRPrecedenceOverGeneratedReverse(t *testing.T) {
	cfg := &Config{Zones: []Zone{
		{
			Name:      "example.org.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    3600,
			TTLAnswer: 300,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
			AMaster:   []IPAddr{{IP: "192.0.2.1", Reverse: true}},
		},
		{
			Name:      "2.0.192.in-addr.arpa.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    3600,
			TTLAnswer: 300,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
			PTR:       []PTRRecord{{Name: "1.2.0.192.in-addr.arpa.", PTR: "explicit.example.org."}},
		},
	}}
	addr, _ := startZonesServer(t, cfg)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("1.2.0.192.in-addr.arpa.", dns.TypePTR)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query PTR: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 PTR answer, got %v", r.Answer)
	}
	if got := r.Answer[0].(*dns.PTR).Ptr; got != "explicit.example.org." {
		t.Fatalf("expected explicit PTR to win, got %q", got)
	}
}

func TestReverseZoneDNSSECDenialForExistingPTROwner(t *testing.T) {
	cfg := &Config{Zones: []Zone{
		{
			Name:      "example.org.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    3600,
			TTLAnswer: 300,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
			AMaster:   []IPAddr{{IP: "192.0.2.1", Reverse: true}},
		},
		{
			Name:      "2.0.192.in-addr.arpa.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    3600,
			TTLAnswer: 300,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
			DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual},
		},
	}}
	addr, auths := startZonesServer(t, cfg)
	revAuth := auths["2.0.192.in-addr.arpa."]
	revAuth.keys = generateTestKeys(t, "2.0.192.in-addr.arpa.")
	revAuth.zidx = buildIndex(revAuth.zone)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("1.2.0.192.in-addr.arpa.", dns.TypeA)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	m.Extra = append(m.Extra, o)

	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query denial: %v", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR/NODATA, got %d", r.Rcode)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected empty answer for NODATA, got %v", r.Answer)
	}

	var sawSOA, sawNSEC, sawRRSIG bool
	for _, rr := range r.Ns {
		switch v := rr.(type) {
		case *dns.SOA:
			sawSOA = true
		case *dns.NSEC:
			sawNSEC = true
			if v.Hdr.Name != "1.2.0.192.in-addr.arpa." {
				t.Fatalf("unexpected NSEC owner %q", v.Hdr.Name)
			}
			foundPTR := false
			for _, typ := range v.TypeBitMap {
				if typ == dns.TypePTR {
					foundPTR = true
				}
			}
			if !foundPTR {
				t.Fatalf("expected PTR type in NSEC bitmap: %v", v.TypeBitMap)
			}
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC {
				sawRRSIG = true
			}
		}
	}
	if !sawSOA || !sawNSEC || !sawRRSIG {
		t.Fatalf("expected SOA, NSEC, and NSEC RRSIG in authority section, got %v", r.Ns)
	}
}
