package main

import (
	"crypto"
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
		TXT:       []TXTRecord{{Name: "sub", Text: []string{"hi"}}},
		DNSSEC:    &DNSSECZoneConfig{Enable: true},
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
	hasNSEC := false
	for _, rr := range r.Ns {
		if _, ok := rr.(*dns.NSEC); ok {
			hasNSEC = true
			break
		}
	}
	if !hasNSEC {
		t.Fatalf("expected NSEC in authority section")
	}
}
