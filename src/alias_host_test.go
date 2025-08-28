package main

import (
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func TestAliasHostResolution(t *testing.T) {
	ensureIPv4(t)
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AliasHost: map[string]string{"www": "localhost."},
	}}}
	config.SetupDefaults(cfg)
	addr, _ := startRecordServer(t, cfg, nil)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)

	m.SetQuestion("www.example.org.", dns.TypeA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "127.0.0.1" {
		t.Fatalf("unexpected A: %v", r.Answer)
	}

	m.SetQuestion("www.example.org.", dns.TypeAAAA)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "::1" {
		t.Fatalf("unexpected AAAA: %v", r.Answer)
	}
}
