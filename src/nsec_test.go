package main

import (
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func containsType(ts []uint16, t uint16) bool {
	for _, v := range ts {
		if v == t {
			return true
		}
	}
	return false
}

func TestMakeNSECTypeFiltering(t *testing.T) {
	z := Zone{
		Name:    "example.com",
		NS:      []string{"ns1.example.net."},
		AMaster: []IPAddr{{IP: "1.1.1.1"}},
		TXT:     []TXTRecord{{Name: "foo.example.com", Text: []string{"bar"}}},
		DNSSEC:  &DNSSECZoneConfig{Mode: DNSSECModeManual},
	}
	idx := buildIndex(z)
	a := &authority{zone: z, zidx: idx}

	apex := a.makeNSEC("example.com")
	if apex == nil {
		t.Fatalf("expected NSEC for apex")
	}
	abm := apex.(*dns.NSEC).TypeBitMap
	for _, tt := range []uint16{dns.TypeSOA, dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeRRSIG} {
		if !containsType(abm, tt) {
			t.Fatalf("apex bitmap missing type %d", tt)
		}
	}

	foo := a.makeNSEC("foo.example.com")
	if foo == nil {
		t.Fatalf("expected NSEC for foo.example.com")
	}
	fbm := foo.(*dns.NSEC).TypeBitMap
	if containsType(fbm, dns.TypeSOA) || containsType(fbm, dns.TypeDNSKEY) {
		t.Fatalf("foo.example.com bitmap should not contain SOA or DNSKEY: %v", fbm)
	}
	for _, tt := range []uint16{dns.TypeNSEC, dns.TypeRRSIG} {
		if !containsType(fbm, tt) {
			t.Fatalf("foo.example.com bitmap missing type %d", tt)
		}
	}
}

func TestApexNSECBitmapMatchesServedAddressFamilies(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:       "example.org.",
		NS:         []string{"ns.example.org."},
		Admin:      "hostmaster.example.org.",
		TTLSOA:     3600,
		TTLAnswer:  300,
		AAAAMaster: []IPAddr{{IP: "2001:db8::1"}},
		AMaster:    []IPAddr{{IP: "192.0.2.1"}},
		DNSSEC:     &DNSSECZoneConfig{Mode: DNSSECModeManual},
	}}}
	config.SetupDefaults(cfg)

	addr, auth := startRecordServer(t, cfg, nil)
	auth.setMasterUp(false, true)
	auth.keys = generateTestKeys(t, cfg.Zones[0].Name)
	auth.zidx = buildIndex(cfg.Zones[0])

	c := &dns.Client{Net: "tcp"}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetDo()

	aaaaMsg := new(dns.Msg)
	aaaaMsg.SetQuestion("example.org.", dns.TypeAAAA)
	aaaaMsg.Extra = append(aaaaMsg.Extra, opt)
	aaaaResp, _, err := c.Exchange(aaaaMsg, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if len(aaaaResp.Answer) == 0 {
		t.Fatalf("expected AAAA answer, got none")
	}
	if _, ok := aaaaResp.Answer[0].(*dns.AAAA); !ok {
		t.Fatalf("expected leading AAAA answer, got %T", aaaaResp.Answer[0])
	}

	aMsg := new(dns.Msg)
	aMsg.SetQuestion("example.org.", dns.TypeA)
	aMsg.Extra = append(aMsg.Extra, opt)
	aResp, _, err := c.Exchange(aMsg, addr)
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	if aResp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR/NODATA for A, got %d", aResp.Rcode)
	}
	if len(aResp.Answer) != 0 {
		t.Fatalf("expected no A answer, got %v", aResp.Answer)
	}

	var apexNSEC *dns.NSEC
	for _, rr := range aResp.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok && nsec.Hdr.Name == "example.org." {
			apexNSEC = nsec
			break
		}
	}
	if apexNSEC == nil {
		t.Fatalf("expected apex NSEC in authority section, got %v", aResp.Ns)
	}
	if containsType(apexNSEC.TypeBitMap, dns.TypeA) {
		t.Fatalf("apex NSEC must not advertise A when apex A is not served: %v", apexNSEC.TypeBitMap)
	}
	if !containsType(apexNSEC.TypeBitMap, dns.TypeAAAA) {
		t.Fatalf("apex NSEC must advertise AAAA when apex AAAA is served: %v", apexNSEC.TypeBitMap)
	}
}
