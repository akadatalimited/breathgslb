package main

import (
	"net"
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startDualStackServer starts a test DNS server listening on both IPv4 and IPv6.
func startDualStackServer(t *testing.T, cfg *Config, gr *geoResolver) (string, string, map[string]*authority) {
	t.Helper()
	mux, auths := buildMux(cfg, gr, nil)
	l4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	l6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("listen tcp6: %v", err)
	}
	srv4 := &dns.Server{Listener: l4, Handler: mux}
	srv6 := &dns.Server{Listener: l6, Handler: mux}
	go func() { _ = srv4.ActivateAndServe() }()
	go func() { _ = srv6.ActivateAndServe() }()
	t.Cleanup(func() { srv4.Shutdown(); srv6.Shutdown() })
	return l4.Addr().String(), l6.Addr().String(), auths
}

func TestDualStackRecords(t *testing.T) {
	cfg := &Config{Zones: []Zone{
		{
			Name:       "dual.example.",
			NS:         []string{"ns1.example."},
			Admin:      "hostmaster.example.",
			TTLSOA:     3600,
			TTLAnswer:  300,
			AMaster:    []IPAddr{{IP: "192.0.2.1"}, {IP: "10.0.0.1"}},
			AAAAMaster: []IPAddr{{IP: "2001:db8::1"}, {IP: "fd00::1"}},
		},
		{
			Name:      "v4only.example.",
			NS:        []string{"ns1.example."},
			Admin:     "hostmaster.example.",
			TTLSOA:    3600,
			TTLAnswer: 300,
			AMaster:   []IPAddr{{IP: "192.0.2.2"}, {IP: "172.16.0.2"}},
		},
		{
			Name:       "v6only.example.",
			NS:         []string{"ns1.example."},
			Admin:      "hostmaster.example.",
			TTLSOA:     3600,
			TTLAnswer:  300,
			AAAAMaster: []IPAddr{{IP: "2001:db8::2"}, {IP: "fd00::2"}},
		},
	}}

	setupDefaults(cfg)
	cfg.DNS64Prefix = ""
	v4addr, v6addr, auths := startDualStackServer(t, cfg, nil)
	for _, a := range auths {
		a.state.master.v4.up = true
		a.state.master.v6.up = true
	}

	c4 := &dns.Client{Net: "tcp4", Timeout: time.Second}
	c6 := &dns.Client{Net: "tcp6", Timeout: time.Second}

	m := new(dns.Msg)

	// dual.example. A over IPv4
	m.SetQuestion("dual.example.", dns.TypeA)
	r, _, err := c4.Exchange(m, v4addr)
	if err != nil {
		t.Fatalf("dual A query: %v", err)
	}
	if len(r.Answer) != 2 {
		t.Fatalf("dual A answers: %v", r.Answer)
	}
	gotA := []string{r.Answer[0].(*dns.A).A.String(), r.Answer[1].(*dns.A).A.String()}
	sort.Strings(gotA)
	wantA := []string{"10.0.0.1", "192.0.2.1"}
	if gotA[0] != wantA[0] || gotA[1] != wantA[1] {
		t.Fatalf("dual A got %v want %v", gotA, wantA)
	}

	// dual.example. AAAA over IPv6
	m.SetQuestion("dual.example.", dns.TypeAAAA)
	r, _, err = c6.Exchange(m, v6addr)
	if err != nil {
		t.Fatalf("dual AAAA query: %v", err)
	}
	if len(r.Answer) != 2 {
		t.Fatalf("dual AAAA answers: %v", r.Answer)
	}
	gotAAAA := []string{r.Answer[0].(*dns.AAAA).AAAA.String(), r.Answer[1].(*dns.AAAA).AAAA.String()}
	sort.Strings(gotAAAA)
	wantAAAA := []string{"2001:db8::1", "fd00::1"}
	if gotAAAA[0] != wantAAAA[0] || gotAAAA[1] != wantAAAA[1] {
		t.Fatalf("dual AAAA got %v want %v", gotAAAA, wantAAAA)
	}

	// v4only.example. A over IPv4
	m.SetQuestion("v4only.example.", dns.TypeA)
	r, _, err = c4.Exchange(m, v4addr)
	if err != nil {
		t.Fatalf("v4only A query: %v", err)
	}
	if len(r.Answer) != 2 {
		t.Fatalf("v4only A answers: %v", r.Answer)
	}
	gotA = []string{r.Answer[0].(*dns.A).A.String(), r.Answer[1].(*dns.A).A.String()}
	sort.Strings(gotA)
	wantA = []string{"172.16.0.2", "192.0.2.2"}
	if gotA[0] != wantA[0] || gotA[1] != wantA[1] {
		t.Fatalf("v4only A got %v want %v", gotA, wantA)
	}

	// v4only.example. AAAA over IPv6 (expect none)
	m.SetQuestion("v4only.example.", dns.TypeAAAA)
	r, _, err = c6.Exchange(m, v6addr)
	if err != nil {
		t.Fatalf("v4only AAAA query: %v", err)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected no AAAA answers for v4only, got %v", r.Answer)
	}

	// v6only.example. AAAA over IPv6
	m.SetQuestion("v6only.example.", dns.TypeAAAA)
	r, _, err = c6.Exchange(m, v6addr)
	if err != nil {
		t.Fatalf("v6only AAAA query: %v", err)
	}
	if len(r.Answer) != 2 {
		t.Fatalf("v6only AAAA answers: %v", r.Answer)
	}
	gotAAAA = []string{r.Answer[0].(*dns.AAAA).AAAA.String(), r.Answer[1].(*dns.AAAA).AAAA.String()}
	sort.Strings(gotAAAA)
	wantAAAA = []string{"2001:db8::2", "fd00::2"}
	if gotAAAA[0] != wantAAAA[0] || gotAAAA[1] != wantAAAA[1] {
		t.Fatalf("v6only AAAA got %v want %v", gotAAAA, wantAAAA)
	}

	// v6only.example. A over IPv4 (expect none)
	m.SetQuestion("v6only.example.", dns.TypeA)
	r, _, err = c4.Exchange(m, v4addr)
	if err != nil {
		t.Fatalf("v6only A query: %v", err)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected no A answers for v6only, got %v", r.Answer)
	}
}
