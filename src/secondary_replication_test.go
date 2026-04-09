package main

import (
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func TestSecondaryAXFR(t *testing.T) {
	ensureIPv4(t)
	mcfg := &Config{Zones: []Zone{{
		Name:       "example.org.",
		NS:         []string{"ns.example.org."},
		Admin:      "hostmaster.example.org.",
		TTLSOA:     3600,
		TTLAnswer:  300,
		Refresh:    1,
		Retry:      1,
		Expire:     60,
		AAAAMaster: []IPAddr{{IP: "2001:db8::1"}},
		AMaster:    []IPAddr{{IP: "192.0.2.1"}},
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
	m.SetQuestion("example.org.", dns.TypeAAAA)
	r, _, err := c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("query secondary AAAA: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::1" {
		t.Fatalf("unexpected AAAA answer from secondary: %v", r.Answer)
	}
	m.SetQuestion("example.org.", dns.TypeA)
	r, _, err = c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("query secondary A: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("unexpected A answer from secondary: %v", r.Answer)
	}

	updatedCfg := &Config{Zones: []Zone{{
		Name:       "example.org.",
		NS:         []string{"ns.example.org."},
		Admin:      "hostmaster.example.org.",
		TTLSOA:     3600,
		TTLAnswer:  300,
		Refresh:    1,
		Retry:      1,
		Expire:     60,
		AAAAMaster: []IPAddr{{IP: "2001:db8::2"}},
		AMaster:    []IPAddr{{IP: "192.0.2.2"}},
	}}}
	config.SetupDefaults(updatedCfg)
	updatedCfg.TimeoutSec = 0
	_, updatedAddr, updatedAuth := startTestServer(t, updatedCfg, nil, nil)
	updatedAuth.cancel()
	sauth.zone.Masters = []string{updatedAddr}

	if err := sauth.transferFromMasters(); err != nil {
		t.Fatalf("refresh transfer: %v", err)
	}
	m.SetQuestion("example.org.", dns.TypeAAAA)
	r, _, err = c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("post-refresh AAAA query: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::2" {
		t.Fatalf("secondary did not refresh to new master AAAA record")
	}
	m.SetQuestion("example.org.", dns.TypeA)
	r, _, err = c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("post-refresh A query: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.2" {
		t.Fatalf("secondary did not refresh to new master A record")
	}
}
