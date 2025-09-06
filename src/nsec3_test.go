package main

import (
	"crypto"
	"strings"
	"testing"

	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// generateTestKeysNSEC3 creates a simple DNSSEC key pair for NSEC3 tests.
func generateTestKeysNSEC3(t *testing.T, zone string) *dnssecKeys {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ensureDot(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("key generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("key not signer")
	}
	return &dnssecKeys{enabled: true, zsk: k, zskPriv: signer, ksk: k, kskPriv: signer, nsec3Iterations: 1, nsec3Salt: ""}
}

func TestNSEC3PARAM(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "foo.example.org.", Text: []string{"bar"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual, NSEC3Iterations: 1, NSEC3Salt: ""},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeysNSEC3(t, cfg.Zones[0].Name)
	auth.zidx = buildIndex(cfg.Zones[0])

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeNSEC3PARAM)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	m.Extra = append(m.Extra, o)
	c := &dns.Client{Net: "tcp"}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %d", r.Rcode)
	}
	var nsec3params []*dns.NSEC3PARAM
	for _, rr := range r.Answer {
		if n, ok := rr.(*dns.NSEC3PARAM); ok {
			nsec3params = append(nsec3params, n)
		}
	}
	if len(nsec3params) != 1 {
		t.Fatalf("expected 1 NSEC3PARAM, got %d", len(nsec3params))
	}
}

func TestNSEC3Denial(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "sub.example.org.", Text: []string{"hi"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual, NSEC3Iterations: 1, NSEC3Salt: ""},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeysNSEC3(t, cfg.Zones[0].Name)
	auth.zidx = buildIndex(cfg.Zones[0])

	m := new(dns.Msg)
	m.SetQuestion("foo.example.org.", dns.TypeA)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	m.Extra = append(m.Extra, o)
	c := &dns.Client{Net: "tcp"}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", r.Rcode)
	}
	var nsec3s []*dns.NSEC3
	var rrsigs []*dns.RRSIG
	for _, rr := range r.Ns {
		switch v := rr.(type) {
		case *dns.NSEC3:
			nsec3s = append(nsec3s, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC3 {
				rrsigs = append(rrsigs, v)
			}
		}
	}
	if len(nsec3s) != 1 {
		t.Fatalf("expected 1 NSEC3, got %d", len(nsec3s))
	}
	if len(rrsigs) == 0 {
		t.Fatalf("expected at least 1 NSEC3 RRSIG, got 0")
	}
}

func TestNSEC3DistinctProofs(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "sub.example.org.", Text: []string{"hi"}}, {Name: "a.example.org.", Text: []string{"hi"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual, NSEC3Iterations: 1, NSEC3Salt: ""},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeysNSEC3(t, cfg.Zones[0].Name)
	auth.zidx = buildIndex(cfg.Zones[0])

	m := new(dns.Msg)
	m.SetQuestion("foo.example.org.", dns.TypeA)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	m.Extra = append(m.Extra, o)
	c := &dns.Client{Net: "tcp"}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", r.Rcode)
	}
	var nsec3s []*dns.NSEC3
	for _, rr := range r.Ns {
		if n, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, n)
		}
	}
	if len(nsec3s) != 2 {
		t.Fatalf("expected 2 NSEC3s, got %d", len(nsec3s))
	}
}

func TestNSEC3OnlyDMARC(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "_dmarc.example.org.", Text: []string{"v=DMARC1"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual, NSEC3Iterations: 1, NSEC3Salt: ""},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeysNSEC3(t, cfg.Zones[0].Name)
	auth.zidx = buildIndex(cfg.Zones[0])

	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	m.Extra = append(m.Extra, o)
	c := &dns.Client{Net: "tcp"}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", r.Rcode)
	}
	nsec3Map := map[string]bool{}
	rrsigMap := map[string]bool{}
	for _, rr := range r.Ns {
		switch v := rr.(type) {
		case *dns.NSEC3:
			key := strings.ToLower(v.Hdr.Name) + "|" + strings.ToLower(v.NextDomain)
			if nsec3Map[key] {
				t.Fatalf("duplicate NSEC3 %s", key)
			}
			nsec3Map[key] = true
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC3 {
				key := strings.ToLower(v.Hdr.Name)
				if rrsigMap[key] {
					t.Fatalf("duplicate RRSIG %s", key)
				}
				rrsigMap[key] = true
			}
		}
	}
	if len(nsec3Map) != 2 {
		t.Fatalf("expected 2 distinct NSEC3s, got %d", len(nsec3Map))
	}
	if len(rrsigMap) != 2 {
		t.Fatalf("expected 2 NSEC3 RRSIGs, got %d", len(rrsigMap))
	}
}

func TestNSEC3NXRRSETNonApex(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "sub.example.org.", Text: []string{"hi"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual, NSEC3Iterations: 1, NSEC3Salt: ""},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeysNSEC3(t, cfg.Zones[0].Name)
	auth.zidx = buildIndex(cfg.Zones[0])

	m := new(dns.Msg)
	m.SetQuestion("sub.example.org.", dns.TypeA)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	m.Extra = append(m.Extra, o)
	c := &dns.Client{Net: "tcp"}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %d", r.Rcode)
	}
	var nsec3 *dns.NSEC3
	for _, rr := range r.Ns {
		if n, ok := rr.(*dns.NSEC3); ok {
			nsec3 = n
			break
		}
	}
	if nsec3 == nil {
		t.Fatalf("expected NSEC3 in authority section")
	}
	for _, typ := range nsec3.TypeBitMap {
		if typ == dns.TypeSOA || typ == dns.TypeDNSKEY {
			t.Fatalf("bitmap contains apex-only type %v", typ)
		}
	}
}