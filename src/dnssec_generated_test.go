package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

// TestDNSSECGenerated verifies DNSSEC generated mode returns signatures and DNSKEYs.
func TestDNSSECGenerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test: relies on Unix file permissions")
	}
	dir := t.TempDir()
	prefix := filepath.Join(dir, "gen")
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		DNSSEC:    &DNSSECZoneConfig{Mode: DNSSECModeGenerated, ZSKFile: prefix, KSKFile: prefix},
	}}}
	config.SetupDefaults(cfg)

	addr, auth := startRecordServer(t, cfg, nil)
	auth.setMasterUp(true, true)

	c := &dns.Client{Net: "tcp"}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()

	// Query an existing A record with DO bit set and expect RRSIG in answer.
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	m.Extra = append(m.Extra, o)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	hasSig := false
	for _, rr := range r.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasSig = true
			break
		}
	}
	if !hasSig {
		t.Fatalf("expected RRSIG in answer section")
	}

	// Query for DNSKEY RRset and ensure DNSKEY records are returned.
	m.SetQuestion("example.org.", dns.TypeDNSKEY)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNSKEY query: %v", err)
	}
	hasKey := false
	for _, rr := range r.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			hasKey = true
			break
		}
	}
	if !hasKey {
		t.Fatalf("expected DNSKEY RRset in answer")
	}
}
