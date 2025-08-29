package main

import (
	"testing"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func TestSecondaryAXFR(t *testing.T) {
	ensureIPv4(t)
	mcfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		Refresh:   1,
		Retry:     1,
		Expire:    60,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
	}}}
	config.SetupDefaults(mcfg)
	mcfg.TimeoutSec = 0
	_, maddr, mAuth := startTestServer(t, mcfg, nil, nil)
	mAuth.cancel()

	scfg := &Config{Zones: []Zone{{
		Name:    "example.org.",
		Serve:   "secondary",
		Masters: []string{maddr},
	}}}
	config.SetupDefaults(scfg)
	scfg.TimeoutSec = 0
	saddr, sauth := startRecordServer(t, scfg, nil)
	sauth.cancel()
	time.Sleep(time.Second)
	if err := sauth.transferFromMasters(); err != nil {
		t.Fatalf("initial transfer: %v", err)
	}

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	r, _, err := c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("query secondary: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("unexpected answer from secondary: %v", r.Answer)
	}

	mAuth.mu.Lock()
	mAuth.zone.AMaster = []IPAddr{{IP: "192.0.2.2"}}
	mAuth.serial++
	mAuth.mu.Unlock()

	if err := sauth.transferFromMasters(); err != nil {
		t.Fatalf("refresh transfer: %v", err)
	}
	m.SetQuestion("example.org.", dns.TypeA)
	r, _, err = c.Exchange(m, saddr)
	if err != nil {
		t.Fatalf("post-refresh query: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.2" {
		t.Fatalf("secondary did not refresh to new master record")
	}
}
