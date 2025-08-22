package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// startRecordServer starts a test DNS server with the provided config and geo resolver.
func startRecordServer(t *testing.T, cfg *Config, gr *geoResolver) (string, *authority) {
	t.Helper()
	mux, auths := buildMux(cfg, gr, nil)
	auth := auths[ensureDot(cfg.Zones[0].Name)]
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{Listener: l, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { srv.Shutdown() })
	return l.Addr().String(), auth
}

func TestRecordTypes(t *testing.T) {
	// Geo resolver placeholder with a cached country/continent for a test IP.
	gr := &geoResolver{
		db:    &maxminddb.Reader{},
		cache: map[string]geoCacheEntry{"203.0.113.9": {country: "US", continent: "NA", exp: time.Now().Add(time.Hour)}},
	}

	cfg := &Config{Zones: []Zone{{
		Name:       "example.org.",
		NS:         []string{"ns.example.org."},
		Admin:      "hostmaster.example.org.",
		TTLSOA:     3600,
		TTLAnswer:  300,
		AMaster:    []IPAddr{{IP: "192.0.2.1"}},
		AAAAMaster: []IPAddr{{IP: "2001:db8::1"}},
		TXT: []TXTRecord{
			{Text: []string{"apex txt"}},
			{Name: "sub.example.org.", Text: []string{"sub txt"}},
		},
		MX: []MXRecord{
			{Preference: 10, Exchange: "mail.example.org."},
			{Name: "sub.example.org.", Preference: 20, Exchange: "mail2.example.org."},
		},
		CAA: []CAARecord{
			{Flag: 0, Tag: "issue", Value: "ca.example.net"},
			{Name: "sub.example.org.", Flag: 0, Tag: "iodef", Value: "mailto:ca@example.net"},
		},
		RP: &RPRecord{Mbox: "mbox.example.org.", Txt: "txt.example.org."},
		SSHFP: []SSHFPRecord{
			{Algorithm: 1, Type: 1, Fingerprint: "1234567890abcdef"},
			{Name: "sub.example.org.", Algorithm: 2, Type: 1, Fingerprint: "abcdef1234567890"},
		},
		SRV: []SRVRecord{
			{Name: "_sip._tcp.example.org.", Priority: 10, Weight: 5, Port: 5060, Target: "sip.example.org."},
			{Name: "_sip._tcp.sub.example.org.", Priority: 20, Weight: 10, Port: 5070, Target: "sip2.example.org."},
		},
		NAPTR: []NAPTRRecord{
			{Name: "@", Order: 100, Preference: 50, Flags: "s", Services: "SIP+D2U", Regexp: "", Replacement: "_sip._udp.example.org."},
			{Name: "sub.example.org.", Order: 100, Preference: 60, Flags: "s", Services: "SIP+D2T", Regexp: "", Replacement: "_sip._tcp.example.org."},
		},
		GeoAnswers: &GeoAnswers{Country: map[string]GeoAnswerSet{
			"US": {A: []string{"198.51.100.5"}, AAAA: []string{"2001:db8::5"}},
		}},
	}}}

	addr, auth := startRecordServer(t, cfg, gr)
	// Mark master up so that default A/AAAA answers exist if geo lookup fails.
	auth.state.mu.Lock()
	auth.state.master.v4.up = true
	auth.state.master.v6.up = true
	auth.state.mu.Unlock()
	if !auth.zidx.types[ensureDot("example.org.")][dns.TypeA] {
		t.Fatalf("A not indexed")
	}

	c := &dns.Client{Net: "tcp"}

	// TXT apex
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeTXT)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("TXT apex query: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.TXT).Txt[0] != "apex txt" {
		t.Fatalf("unexpected TXT apex answer: %v", r.Answer)
	}

	// TXT subdomain
	m.SetQuestion("sub.example.org.", dns.TypeTXT)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("TXT sub query: %v", err)
	}
	if len(r.Answer) != 1 || r.Answer[0].(*dns.TXT).Txt[0] != "sub txt" {
		t.Fatalf("unexpected TXT sub answer: %v", r.Answer)
	}

	// MX apex
	m.SetQuestion("example.org.", dns.TypeMX)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("MX apex query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 MX answer, got %v", r.Answer)
	}
	mx := r.Answer[0].(*dns.MX)
	if mx.Preference != 10 || mx.Mx != "mail.example.org." {
		t.Fatalf("unexpected MX apex: %v", mx)
	}

	// MX subdomain
	m.SetQuestion("sub.example.org.", dns.TypeMX)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("MX sub query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 MX sub answer, got %v", r.Answer)
	}
	mx = r.Answer[0].(*dns.MX)
	if mx.Preference != 20 || mx.Mx != "mail2.example.org." {
		t.Fatalf("unexpected MX sub: %v", mx)
	}

	// CAA apex
	m.SetQuestion("example.org.", dns.TypeCAA)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("CAA apex query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 CAA apex answer, got %v", r.Answer)
	}
	caa := r.Answer[0].(*dns.CAA)
	if caa.Flag != 0 || caa.Tag != "issue" || caa.Value != "ca.example.net" {
		t.Fatalf("unexpected CAA apex: %v", caa)
	}

	// CAA subdomain
	m.SetQuestion("sub.example.org.", dns.TypeCAA)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("CAA sub query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 CAA sub answer, got %v", r.Answer)
	}
	caa = r.Answer[0].(*dns.CAA)
	if caa.Tag != "iodef" || caa.Value != "mailto:ca@example.net" {
		t.Fatalf("unexpected CAA sub: %v", caa)
	}

	// RP apex
	m.SetQuestion("example.org.", dns.TypeRP)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("RP apex query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 RP answer, got %v", r.Answer)
	}
	rp := r.Answer[0].(*dns.RP)
	if rp.Mbox != "mbox.example.org." || rp.Txt != "txt.example.org." {
		t.Fatalf("unexpected RP apex: %v", rp)
	}

	// SSHFP apex
	m.SetQuestion("example.org.", dns.TypeSSHFP)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("SSHFP apex query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 SSHFP apex answer, got %v", r.Answer)
	}
	ssh := r.Answer[0].(*dns.SSHFP)
	if ssh.Algorithm != 1 || ssh.Type != 1 || ssh.FingerPrint != "1234567890abcdef" {
		t.Fatalf("unexpected SSHFP apex: %v", ssh)
	}

	// SSHFP subdomain
	m.SetQuestion("sub.example.org.", dns.TypeSSHFP)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("SSHFP sub query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 SSHFP sub answer, got %v", r.Answer)
	}
	ssh = r.Answer[0].(*dns.SSHFP)
	if ssh.Algorithm != 2 || ssh.Type != 1 || ssh.FingerPrint != "abcdef1234567890" {
		t.Fatalf("unexpected SSHFP sub: %v", ssh)
	}

	// SRV apex
	m.SetQuestion("_sip._tcp.example.org.", dns.TypeSRV)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("SRV apex query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 SRV apex answer, got %v", r.Answer)
	}
	srv := r.Answer[0].(*dns.SRV)
	if srv.Priority != 10 || srv.Weight != 5 || srv.Port != 5060 || srv.Target != "sip.example.org." {
		t.Fatalf("unexpected SRV apex: %v", srv)
	}

	// SRV subdomain
	m.SetQuestion("_sip._tcp.sub.example.org.", dns.TypeSRV)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("SRV sub query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 SRV sub answer, got %v", r.Answer)
	}
	srv = r.Answer[0].(*dns.SRV)
	if srv.Priority != 20 || srv.Weight != 10 || srv.Port != 5070 || srv.Target != "sip2.example.org." {
		t.Fatalf("unexpected SRV sub: %v", srv)
	}

	// NAPTR apex
	m.SetQuestion("example.org.", dns.TypeNAPTR)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("NAPTR apex query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 NAPTR apex answer, got %v", r.Answer)
	}
	nap := r.Answer[0].(*dns.NAPTR)
	if nap.Order != 100 || nap.Preference != 50 || nap.Flags != "s" || nap.Service != "SIP+D2U" || nap.Replacement != "_sip._udp.example.org." {
		t.Fatalf("unexpected NAPTR apex: %v", nap)
	}

	// NAPTR subdomain
	m.SetQuestion("sub.example.org.", dns.TypeNAPTR)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("NAPTR sub query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 NAPTR sub answer, got %v", r.Answer)
	}
	nap = r.Answer[0].(*dns.NAPTR)
	if nap.Order != 100 || nap.Preference != 60 || nap.Flags != "s" || nap.Service != "SIP+D2T" || nap.Replacement != "_sip._tcp.example.org." {
		t.Fatalf("unexpected NAPTR sub: %v", nap)
	}

}
