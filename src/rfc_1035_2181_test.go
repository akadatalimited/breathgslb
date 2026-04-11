package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func startRFCUDPServer(t *testing.T, cfg *Config) (string, *authority) {
	t.Helper()
	ensureIPv4(t)
	oldDisable := cfg.DisableBackgroundLoops
	cfg.DisableBackgroundLoops = true
	t.Cleanup(func() { cfg.DisableBackgroundLoops = oldDisable })
	mux, auths := buildMux(cfg, nil, nil, nil)
	auth := auths[ensureDot(cfg.Zones[0].Name)]
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	t.Cleanup(auth.cancel)
	return pc.LocalAddr().String(), auth
}

func TestRFC1035And3596AdditionalSectionProcessing(t *testing.T) {
	ensureIPv4(t)
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		MX:        []MXRecord{{Name: "example.org.", Preference: 10, Exchange: "mail.example.org."}},
		SRV:       []SRVRecord{{Name: "_sip._tcp.example.org.", Priority: 10, Weight: 5, Port: 5060, Target: "sip.example.org."}},
		Hosts: []Host{
			{
				Name: "ns",
				Pools: []Pool{
					{Name: "ns-v6", Family: "ipv6", Role: "fallback", Members: []IPAddr{{IP: "2001:db8::53"}}},
					{Name: "ns-v4", Family: "ipv4", Role: "fallback", Members: []IPAddr{{IP: "192.0.2.53"}}},
				},
			},
			{
				Name: "mail",
				Pools: []Pool{
					{Name: "mail-v6", Family: "ipv6", Role: "fallback", Members: []IPAddr{{IP: "2001:db8::25"}}},
					{Name: "mail-v4", Family: "ipv4", Role: "fallback", Members: []IPAddr{{IP: "192.0.2.25"}}},
				},
			},
			{
				Name: "sip",
				Pools: []Pool{
					{Name: "sip-v6", Family: "ipv6", Role: "fallback", Members: []IPAddr{{IP: "2001:db8::5060"}}},
					{Name: "sip-v4", Family: "ipv4", Role: "fallback", Members: []IPAddr{{IP: "192.0.2.60"}}},
				},
			},
		},
	}}}
	config.SetupDefaults(cfg)

	addr, _ := startRecordServer(t, cfg, nil)
	c := &dns.Client{Net: "tcp"}

	tests := []struct {
		name     string
		qname    string
		qtype    uint16
		targetV4 string
		targetV6 string
	}{
		{name: "NS", qname: "example.org.", qtype: dns.TypeNS, targetV4: "192.0.2.53", targetV6: "2001:db8::53"},
		{name: "MX", qname: "example.org.", qtype: dns.TypeMX, targetV4: "192.0.2.25", targetV6: "2001:db8::25"},
		{name: "SRV", qname: "_sip._tcp.example.org.", qtype: dns.TypeSRV, targetV4: "192.0.2.60", targetV6: "2001:db8::5060"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(tt.qname, tt.qtype)
			r, _, err := c.Exchange(m, addr)
			if err != nil {
				t.Fatalf("query %s: %v", dns.TypeToString[tt.qtype], err)
			}
			var sawV4, sawV6 bool
			for _, rr := range r.Extra {
				switch v := rr.(type) {
				case *dns.A:
					if v.A.String() == tt.targetV4 {
						sawV4 = true
					}
				case *dns.AAAA:
					if v.AAAA.String() == tt.targetV6 {
						sawV6 = true
					}
				}
			}
			if !sawV4 || !sawV6 {
				t.Fatalf("expected A and AAAA additional data for %s, got extra=%v", tt.qname, r.Extra)
			}
		})
	}
}

func TestRFC2181TCSetWhenRRSetDoesNotFitUDP(t *testing.T) {
	ensureIPv4(t)
	var addrs []IPAddr
	for i := 1; i <= 40; i++ {
		addrs = append(addrs, IPAddr{IP: fmt.Sprintf("2001:db8::%x", i)})
	}
	cfg := &Config{Zones: []Zone{{
		Name:       "example.org.",
		NS:         []string{"ns.example.org."},
		Admin:      "hostmaster.example.org.",
		TTLSOA:     3600,
		TTLAnswer:  300,
		AAAAMaster: addrs,
	}}}
	config.SetupDefaults(cfg)
	cfg.MaxRecords = 0

	addr, auth := startRFCUDPServer(t, cfg)
	auth.setMasterUp(true, true)

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeAAAA)
	m.SetEdns0(512, false)
	c := &dns.Client{Net: "udp"}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if !r.Truncated {
		t.Fatalf("expected TC=1 when full AAAA RRSet does not fit, got %#v", r)
	}
	if len(r.Answer) == 0 || len(r.Answer) >= len(addrs) {
		t.Fatalf("expected truncated subset of AAAA RRSet, got %d answers for %d records", len(r.Answer), len(addrs))
	}
}

func TestRFC2181AXFRReturnsWholeRRSet(t *testing.T) {
	ensureIPv4(t)
	cfg := &Config{Zones: []Zone{{
		Name:       "example.org.",
		NS:         []string{"ns.example.org."},
		Admin:      "hostmaster.example.org.",
		TTLSOA:     3600,
		TTLAnswer:  300,
		AMaster:    []IPAddr{{IP: "192.0.2.1"}, {IP: "192.0.2.2"}, {IP: "192.0.2.3"}},
		AAAAMaster: []IPAddr{{IP: "2001:db8::1"}, {IP: "2001:db8::2"}, {IP: "2001:db8::3"}},
	}}}
	config.SetupDefaults(cfg)
	cfg.MaxRecords = 1

	addr, auth := startRecordServer(t, cfg, nil)
	auth.setMasterUp(true, true)

	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	tr := new(dns.Transfer)
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	var all []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("AXFR envelope: %v", e.Error)
		}
		all = append(all, e.RR...)
	}
	var countA, countAAAA int
	for _, rr := range all {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			countA++
		case dns.TypeAAAA:
			countAAAA++
		}
	}
	if countA != 3 || countAAAA != 3 {
		t.Fatalf("expected full RRsets in AXFR despite max_records=1, got A=%d AAAA=%d records=%v", countA, countAAAA, all)
	}
}
