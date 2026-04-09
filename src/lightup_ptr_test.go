package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func lightupPTRZoneConfig() *Config {
	return &Config{Zones: []Zone{
		{
			Name:      "lightitup.zerodns.co.uk.",
			NS:        []string{"gslb.zerodns.co.uk."},
			Admin:     "hostmaster.zerodns.co.uk.",
			TTLSOA:    300,
			TTLAnswer: 60,
			Refresh:   300,
			Retry:     60,
			Expire:    3600,
			Minttl:    60,
			Lightup: &LightupConfig{
				Enabled:  true,
				Reverse:  true,
				Strategy: "hash",
				Families: []LightupFamily{{
					Family:      "ipv6",
					Class:       "public",
					Prefix:      "2a02:8012:bc57:5353::/64",
					RespondPTR:  true,
					RespondAAAA: true,
					Exclude: []string{
						"2a02:8012:bc57:5353::1/128",
						"2a02:8012:bc57:5353::53/128",
					},
				}},
			},
		},
		{
			Name:      "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.",
			NS:        []string{"gslb.zerodns.co.uk."},
			Admin:     "hostmaster.zerodns.co.uk.",
			TTLSOA:    300,
			TTLAnswer: 300,
			Refresh:   300,
			Retry:     60,
			Expire:    3600,
			Minttl:    60,
		},
	}}
}

func reverseOwnerForIP(t *testing.T, ip string) string {
	t.Helper()
	owner, err := dns.ReverseAddr(ip)
	if err != nil {
		t.Fatalf("ReverseAddr(%q): %v", ip, err)
	}
	return owner
}

func TestLightupSynthesizedPTR(t *testing.T) {
	cfg := lightupPTRZoneConfig()
	addr, _ := startZonesServer(t, cfg)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion(reverseOwnerForIP(t, "2a02:8012:bc57:5353::111"), dns.TypePTR)

	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query PTR: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 PTR answer, got %v", r.Answer)
	}
	got := r.Answer[0].(*dns.PTR).Ptr
	want := "addr-2a02-8012-bc57-5353-0000-0000-0000-0111.lightitup.zerodns.co.uk."
	if got != want {
		t.Fatalf("unexpected PTR target got %q want %q", got, want)
	}
}

func TestLightupExplicitPTRBeatsSynthetic(t *testing.T) {
	cfg := lightupPTRZoneConfig()
	cfg.Zones[1].PTR = []PTRRecord{{
		Name: reverseOwnerForIP(t, "2a02:8012:bc57:5353::111"),
		PTR:  "explicit.lightitup.zerodns.co.uk.",
	}}
	addr, _ := startZonesServer(t, cfg)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion(reverseOwnerForIP(t, "2a02:8012:bc57:5353::111"), dns.TypePTR)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query PTR: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 PTR answer, got %v", r.Answer)
	}
	if got := r.Answer[0].(*dns.PTR).Ptr; got != "explicit.lightitup.zerodns.co.uk." {
		t.Fatalf("expected explicit PTR to win, got %q", got)
	}
}

func TestLightupPTRPrimarySecondaryConsistency(t *testing.T) {
	primaryCfg := lightupPTRZoneConfig()
	primaryAddr, _ := startZonesServer(t, primaryCfg)

	secondaryCfg := lightupPTRZoneConfig()
	secondaryCfg.Zones[1] = Zone{
		Name:    "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.",
		Serve:   "secondary",
		Masters: []string{primaryAddr},
	}
	secondaryAddr, auths := startZonesServer(t, secondaryCfg)
	secondary := auths["3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa."]
	if err := secondary.transferFromMasters(); err != nil {
		t.Fatalf("initial transfer: %v", err)
	}

	qname := reverseOwnerForIP(t, "2a02:8012:bc57:5353::111")
	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypePTR)

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
	if gotPrimary != gotSecondary {
		t.Fatalf("PTR mismatch primary=%q secondary=%q", gotPrimary, gotSecondary)
	}
}

func TestLightupReverseZoneDNSSECDenialForSyntheticPTROwner(t *testing.T) {
	cfg := lightupPTRZoneConfig()
	cfg.Zones[1].DNSSEC = &DNSSECZoneConfig{Mode: DNSSECModeManual}
	addr, auths := startZonesServer(t, cfg)
	revAuth := auths["3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa."]
	revAuth.keys = generateTestKeys(t, cfg.Zones[1].Name)
	revAuth.zidx = buildIndex(revAuth.zone)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion(reverseOwnerForIP(t, "2a02:8012:bc57:5353::111"), dns.TypeA)
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
	var sawNSEC bool
	for _, rr := range r.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			sawNSEC = true
			if !containsType(nsec.TypeBitMap, dns.TypePTR) {
				t.Fatalf("expected PTR type in NSEC bitmap: %v", nsec.TypeBitMap)
			}
		}
	}
	if !sawNSEC {
		t.Fatalf("expected NSEC proof, got %v", r.Ns)
	}
}

func TestLightupReverseZoneNSEC3DenialForSyntheticPTROwner(t *testing.T) {
	cfg := lightupPTRZoneConfig()
	cfg.Zones[1].DNSSEC = &DNSSECZoneConfig{Mode: DNSSECModeManual, NSEC3Iterations: 1}
	addr, auths := startZonesServer(t, cfg)
	revAuth := auths["3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa."]
	revAuth.keys = generateTestKeysNSEC3(t, cfg.Zones[1].Name)
	revAuth.zidx = buildIndex(revAuth.zone)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion(reverseOwnerForIP(t, "2a02:8012:bc57:5353::111"), dns.TypeA)
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
	var sawNSEC3 bool
	for _, rr := range r.Ns {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			sawNSEC3 = true
			if !containsType(nsec3.TypeBitMap, dns.TypePTR) {
				t.Fatalf("expected PTR type in NSEC3 bitmap: %v", nsec3.TypeBitMap)
			}
		}
	}
	if !sawNSEC3 {
		t.Fatalf("expected NSEC3 proof, got %v", r.Ns)
	}
}

func TestParseIPv6ReverseOwner(t *testing.T) {
	ip, ok := parseIPv6ReverseOwner(reverseOwnerForIP(t, "2a02:8012:bc57:5353::111"))
	if !ok {
		t.Fatalf("expected reverse owner to parse")
	}
	if !ip.Equal(net.ParseIP("2a02:8012:bc57:5353::111")) {
		t.Fatalf("unexpected IP %v", ip)
	}
}
