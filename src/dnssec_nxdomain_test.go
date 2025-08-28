package main

import (
	"crypto"
	"strings"
	"testing"

	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// generateTestKeys creates a simple DNSSEC key pair for tests.
func generateTestKeys(t *testing.T, zone string) *dnssecKeys {
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
	return &dnssecKeys{enabled: true, zsk: k, zskPriv: signer, ksk: k, kskPriv: signer}
}

func TestDNSSECNXDOMAIN(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "sub.example.org.", Text: []string{"hi"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeys(t, cfg.Zones[0].Name)
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
	var nsecs []*dns.NSEC
	var rrsigs []*dns.RRSIG
	for _, rr := range r.Ns {
		switch v := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC {
				rrsigs = append(rrsigs, v)
			}
		}
	}
	if len(nsecs) != 1 {
		t.Fatalf("expected 1 NSEC, got %d", len(nsecs))
	}
	if len(rrsigs) == 0 {
		t.Fatalf("expected at least 1 NSEC RRSIG, got 0")
	}
}

func TestDNSSECNXDOMAINDistinctProofs(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "sub.example.org.", Text: []string{"hi"}}, {Name: "a.example.org.", Text: []string{"hi"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeys(t, cfg.Zones[0].Name)
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
	var nsecs []*dns.NSEC
	for _, rr := range r.Ns {
		if n, ok := rr.(*dns.NSEC); ok {
			nsecs = append(nsecs, n)
		}
	}
	if len(nsecs) != 2 {
		t.Fatalf("expected 2 NSECs, got %d", len(nsecs))
	}
}

func TestDNSSECNXDOMAINOnlyDMARC(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "_dmarc.example.org.", Text: []string{"v=DMARC1"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeys(t, cfg.Zones[0].Name)
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
	nsecMap := map[string]bool{}
	rrsigMap := map[string]bool{}
	for _, rr := range r.Ns {
		switch v := rr.(type) {
		case *dns.NSEC:
			key := strings.ToLower(v.Hdr.Name) + "|" + strings.ToLower(v.NextDomain)
			if nsecMap[key] {
				t.Fatalf("duplicate NSEC %s", key)
			}
			nsecMap[key] = true
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC {
				key := strings.ToLower(v.Hdr.Name)
				if rrsigMap[key] {
					t.Fatalf("duplicate RRSIG %s", key)
				}
				rrsigMap[key] = true
			}
		}
	}
	if len(nsecMap) != 2 {
		t.Fatalf("expected 2 distinct NSECs, got %d", len(nsecMap))
	}
	if len(rrsigMap) != 2 {
		t.Fatalf("expected 2 NSEC RRSIGs, got %d", len(rrsigMap))
	}
}

func TestDNSSECNXRRSETNonApex(t *testing.T) {
	gr := &geoResolver{db: &maxminddb.Reader{}, cache: map[string]geoCacheEntry{}}
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TXT:       []TXTRecord{{Name: "sub.example.org.", Text: []string{"hi"}}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeManual},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	auth.setMasterUp(true, true)
	auth.keys = generateTestKeys(t, cfg.Zones[0].Name)
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
	var nsec *dns.NSEC
	for _, rr := range r.Ns {
		if n, ok := rr.(*dns.NSEC); ok {
			nsec = n
			break
		}
	}
	if nsec == nil {
		t.Fatalf("expected NSEC in authority section")
	}
	for _, typ := range nsec.TypeBitMap {
		if typ == dns.TypeSOA || typ == dns.TypeDNSKEY {
			t.Fatalf("bitmap contains apex-only type %v", typ)
		}
	}
}
