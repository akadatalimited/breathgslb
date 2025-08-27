package main

import (
	"testing"

	"github.com/miekg/dns"
)

// TestRecursionDisabled ensures the server does not provide recursive answers
// for queries outside the served zones.
func TestRecursionDisabled(t *testing.T) {
	cfg := &Config{EDNSBuf: 1232, Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "203.0.113.1"}},
	}}}

	addr, _ := startRecordServer(t, cfg, nil)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("nonexistent.tld.", dns.TypeA)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.RecursionAvailable {
		t.Fatalf("expected recursion to be disabled")
	}
	if r.Rcode == dns.RcodeSuccess {
		t.Fatalf("unexpected successful answer for non-authoritative query")
	}
}
