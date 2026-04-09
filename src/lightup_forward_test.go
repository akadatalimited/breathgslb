package main

import (
	"net"
	"strings"
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func forwardLightupConfig() *Config {
	return &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    300,
		TTLAnswer: 60,
		Refresh:   300,
		Retry:     60,
		Expire:    3600,
		Minttl:    60,
		Lightup: &LightupConfig{
			Enabled:  true,
			Forward:  true,
			Strategy: "hash",
			Families: []LightupFamily{{
				Family:      "ipv6",
				Class:       "public",
				Prefix:      "2001:db8:5353::/64",
				RespondAAAA: true,
				Exclude:     []string{"2001:db8:5353::1/128"},
			}},
		},
	}}}
}

func forwardTemplateLightupConfig() *Config {
	cfg := forwardLightupConfig()
	cfg.Zones[0].Lightup.ForwardTemplate = "addr-{addr}.example.org."
	return cfg
}

func forwardReverseLightupConfig() *Config {
	return &Config{Zones: []Zone{
		{
			Name:      "example.org.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    300,
			TTLAnswer: 60,
			Refresh:   300,
			Retry:     60,
			Expire:    3600,
			Minttl:    60,
			Lightup: &LightupConfig{
				Enabled:         true,
				Forward:         true,
				Reverse:         true,
				Strategy:        "hash",
				ForwardTemplate: "addr-{addr}.example.org.",
				Families: []LightupFamily{{
					Family:      "ipv6",
					Class:       "public",
					Prefix:      "2001:db8:5353::/64",
					RespondAAAA: true,
					RespondPTR:  true,
					Exclude: []string{
						"2001:db8:5353::1/128",
						"2001:db8:5353::53/128",
					},
				}},
			},
		},
		{
			Name:      "0.0.0.0.3.5.3.5.8.b.d.0.1.0.0.2.ip6.arpa.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    300,
			TTLAnswer: 60,
			Refresh:   300,
			Retry:     60,
			Expire:    3600,
			Minttl:    60,
		},
	}}
}

func forwardReverseDualStackLightupConfig() *Config {
	cfg := forwardReverseLightupConfig()
	cfg.Zones[0].Lightup.Families = append(cfg.Zones[0].Lightup.Families, LightupFamily{
		Family:    "ipv4",
		Class:     "private",
		Prefix:    "172.16.0.0/24",
		RespondA:  true,
		RespondPTR: true,
		Exclude: []string{
			"172.16.0.1/32",
			"172.16.0.2/32",
		},
	})
	cfg.Zones = append(cfg.Zones, Zone{
		Name:      "0.16.172.in-addr.arpa.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    300,
		TTLAnswer: 300,
		Refresh:   300,
		Retry:     60,
		Expire:    3600,
		Minttl:    60,
	})
	return cfg
}

func TestLightupForwardDeterministicAndDistinct(t *testing.T) {
	cfg := forwardLightupConfig()
	specs := compileLightupSpecs(cfg.Zones)
	if len(specs) != 1 {
		t.Fatalf("expected one lightup spec, got %d", len(specs))
	}
	spec := specs[0]
	a := lightupAddressForName(spec, "host1.example.org.")
	b := lightupAddressForName(spec, "host1.example.org.")
	c := lightupAddressForName(spec, "host2.example.org.")
	if a == nil || b == nil || c == nil {
		t.Fatalf("expected synthesized addresses, got a=%v b=%v c=%v", a, b, c)
	}
	if !a.Equal(b) {
		t.Fatalf("same name must map to same IPv6: %v vs %v", a, b)
	}
	if a.Equal(c) {
		t.Fatalf("different names must map to different IPv6: %v vs %v", a, c)
	}
}

func TestLightupForwardExcludedPrefixAvoided(t *testing.T) {
	spec := lightupRuntimeSpec{
		zoneName:    "example.org.",
		class:       "public",
		respondAAAA: true,
	}
	_, prefixNet, err := net.ParseCIDR("2001:db8::/126")
	if err != nil {
		t.Fatalf("ParseCIDR prefix: %v", err)
	}
	spec.prefix = prefixNet
	for _, raw := range []string{"2001:db8::/127", "2001:db8::2/128"} {
		_, exNet, err := net.ParseCIDR(raw)
		if err != nil {
			t.Fatalf("ParseCIDR exclude %q: %v", raw, err)
		}
		spec.exclude = append(spec.exclude, exNet)
	}
	ip := lightupAddressForName(spec, "host.example.org.")
	if ip == nil {
		t.Fatalf("expected synthesized IPv6 address")
	}
	if got := ip.String(); got != "2001:db8::3" {
		t.Fatalf("expected only non-excluded address 2001:db8::3, got %s", got)
	}
}

func TestLightupForwardConfiguredAAAABeatsSynthetic(t *testing.T) {
	cfg := forwardLightupConfig()
	cfg.Zones[0].AAAAMaster = []IPAddr{{IP: "2001:db8::1"}}
	config.SetupDefaults(cfg)
	addr, auth := startRecordServer(t, cfg, nil)
	auth.setMasterUp(false, true)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeAAAA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected one AAAA answer, got %v", r.Answer)
	}
	got := r.Answer[0].(*dns.AAAA).AAAA.String()
	if got != "2001:db8::1" {
		t.Fatalf("expected configured apex AAAA to win, got %s", got)
	}
}

func TestLightupForwardDNSSECSignedAAAA(t *testing.T) {
	cfg := forwardLightupConfig()
	cfg.Zones[0].DNSSEC = &DNSSECZoneConfig{Mode: DNSSECModeManual}
	config.SetupDefaults(cfg)
	addr, auth := startRecordServer(t, cfg, nil)
	auth.keys = generateTestKeys(t, cfg.Zones[0].Name)
	auth.zidx = buildIndex(cfg.Zones[0])
	if got := auth.lightupAAAARecords("host.example.org.", net.ParseIP("127.0.0.1")); len(got) == 0 {
		t.Fatalf("expected helper to synthesize AAAA before query")
	}
	if got := auth.addrAAAA("host.example.org.", net.ParseIP("127.0.0.1"), new(dns.Msg)); len(got) == 0 {
		t.Fatalf("expected addrAAAA to synthesize AAAA before query")
	}

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("host.example.org.", dns.TypeAAAA)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	m.Extra = append(m.Extra, o)

	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	var sawAAAA, sawRRSIG bool
	for _, rr := range r.Answer {
		switch rr.(type) {
		case *dns.AAAA:
			sawAAAA = true
		case *dns.RRSIG:
			sawRRSIG = true
		}
	}
	if !sawAAAA || !sawRRSIG {
		t.Fatalf("expected signed synthetic AAAA answer, rcode=%d answer=%v ns=%v", r.Rcode, r.Answer, r.Ns)
	}
}

func TestLightupForwardULAPreference(t *testing.T) {
	cfg := forwardLightupConfig()
	cfg.Zones[0].Lightup.Families = []LightupFamily{
		{
			Family:      "ipv6",
			Class:       "public",
			Prefix:      "2001:db8:5353::/64",
			RespondAAAA: true,
		},
		{
			Family:      "ipv6",
			Class:       "ula",
			Prefix:      "fd00:5353::/64",
			RespondAAAA: true,
		},
	}
	config.SetupDefaults(cfg)
	_, auth := startRecordServer(t, cfg, nil)

	publicRRs := auth.lightupAAAARecords("host.example.org.", net.ParseIP("2001:db8::10"))
	if len(publicRRs) != 1 {
		t.Fatalf("expected public synthesized AAAA, got %v", publicRRs)
	}
	publicIP := publicRRs[0].(*dns.AAAA).AAAA
	if !stringsHasPrefixFold(publicIP.String(), "2001:db8:5353:") {
		t.Fatalf("expected public prefix, got %s", publicIP)
	}

	ulaRRs := auth.lightupAAAARecords("host.example.org.", net.ParseIP("fd00::10"))
	if len(ulaRRs) != 1 {
		t.Fatalf("expected ULA synthesized AAAA, got %v", ulaRRs)
	}
	ulaIP := ulaRRs[0].(*dns.AAAA).AAAA
	if !stringsHasPrefixFold(ulaIP.String(), "fd00:5353:") {
		t.Fatalf("expected ULA prefix, got %s", ulaIP)
	}
}

func TestLightupForwardPrimarySecondaryConsistency(t *testing.T) {
	primaryCfg := forwardLightupConfig()
	primaryCfg.Zones[0].DNSSEC = &DNSSECZoneConfig{Mode: DNSSECModeManual}
	config.SetupDefaults(primaryCfg)
	_, primaryAddr, primaryAuth := startTestServer(t, primaryCfg, nil, nil)
	keys := generateTestKeys(t, primaryCfg.Zones[0].Name)
	primaryAuth.keys = keys
	primaryAuth.zidx = buildIndex(primaryCfg.Zones[0])
	if got := primaryAuth.lightupAAAARecords("host.example.org.", net.ParseIP("127.0.0.1")); len(got) == 0 {
		t.Fatalf("expected primary helper to synthesize AAAA before query")
	}
	if got := primaryAuth.addrAAAA("host.example.org.", net.ParseIP("127.0.0.1"), new(dns.Msg)); len(got) == 0 {
		t.Fatalf("expected primary addrAAAA to synthesize AAAA before query")
	}

	secondaryCfg := forwardLightupConfig()
	secondaryCfg.Zones[0].Serve = "secondary"
	secondaryCfg.Zones[0].DNSSEC = &DNSSECZoneConfig{Mode: DNSSECModeManual}
	secondaryCfg.Zones[0].Masters = nil
	config.SetupDefaults(secondaryCfg)
	_, secondaryAddr, secondaryAuth := startTestServer(t, secondaryCfg, nil, nil)
	secondaryAuth.keys = keys
	secondaryAuth.zone.Masters = []string{primaryAddr}
	if err := secondaryAuth.transferFromMasters(); err != nil {
		t.Fatalf("initial transfer: %v", err)
	}

	c := &dns.Client{Net: "tcp"}
	q := new(dns.Msg)
	q.SetQuestion("host.example.org.", dns.TypeAAAA)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	q.Extra = append(q.Extra, o)

	primaryResp, _, err := c.Exchange(q, primaryAddr)
	if err != nil {
		t.Fatalf("query primary: %v", err)
	}
	secondaryResp, _, err := c.Exchange(q, secondaryAddr)
	if err != nil {
		t.Fatalf("query secondary: %v", err)
	}
	if len(primaryResp.Answer) == 0 || len(secondaryResp.Answer) == 0 {
		t.Fatalf("expected synthesized AAAA on both nodes, primary=%v secondary=%v", primaryResp.Answer, secondaryResp.Answer)
	}
	primaryAAAA := primaryResp.Answer[0].(*dns.AAAA).AAAA.String()
	secondaryAAAA := secondaryResp.Answer[0].(*dns.AAAA).AAAA.String()
	if primaryAAAA != secondaryAAAA {
		t.Fatalf("primary/secondary synthesized AAAA mismatch: %s vs %s", primaryAAAA, secondaryAAAA)
	}
}

func TestLightupForwardExactRoundTripSymmetry(t *testing.T) {
	cfg := forwardReverseLightupConfig()
	addr, _ := startZonesServer(t, cfg)

	targetIP := "2001:db8:5353::111"
	c := &dns.Client{Net: "tcp"}

	ptrQ := new(dns.Msg)
	ptrQ.SetQuestion(reverseOwnerForIP(t, targetIP), dns.TypePTR)
	ptrResp, _, err := c.Exchange(ptrQ, addr)
	if err != nil {
		t.Fatalf("PTR query: %v", err)
	}
	if len(ptrResp.Answer) != 1 {
		t.Fatalf("expected one PTR answer, got %v", ptrResp.Answer)
	}
	ptrName := ptrResp.Answer[0].(*dns.PTR).Ptr

	aaaaQ := new(dns.Msg)
	aaaaQ.SetQuestion(ptrName, dns.TypeAAAA)
	aaaaResp, _, err := c.Exchange(aaaaQ, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if len(aaaaResp.Answer) != 1 {
		t.Fatalf("expected one AAAA answer, got %v", aaaaResp.Answer)
	}
	if got := aaaaResp.Answer[0].(*dns.AAAA).AAAA.String(); got != targetIP {
		t.Fatalf("expected round-trip AAAA %s, got %s", targetIP, got)
	}
}

func TestLightupForwardTemplateDrivesPTRNameWhenNoPTRTemplateSet(t *testing.T) {
	cfg := forwardReverseLightupConfig()
	cfg.Zones[0].Lightup.ForwardTemplate = "fresh-{addr}.example.org."
	cfg.Zones[0].Lightup.PTRTemplate = ""
	addr, _ := startZonesServer(t, cfg)

	targetIP := "2001:db8:5353::111"
	c := &dns.Client{Net: "tcp"}

	ptrQ := new(dns.Msg)
	ptrQ.SetQuestion(reverseOwnerForIP(t, targetIP), dns.TypePTR)
	ptrResp, _, err := c.Exchange(ptrQ, addr)
	if err != nil {
		t.Fatalf("PTR query: %v", err)
	}
	if len(ptrResp.Answer) != 1 {
		t.Fatalf("expected one PTR answer, got %v", ptrResp.Answer)
	}
	ptrName := ptrResp.Answer[0].(*dns.PTR).Ptr
	want := "fresh-2001-0db8-5353-0000-0000-0000-0000-0111.example.org."
	if ptrName != want {
		t.Fatalf("expected PTR target %s, got %s", want, ptrName)
	}

	aaaaQ := new(dns.Msg)
	aaaaQ.SetQuestion(ptrName, dns.TypeAAAA)
	aaaaResp, _, err := c.Exchange(aaaaQ, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if len(aaaaResp.Answer) != 1 {
		t.Fatalf("expected one AAAA answer, got %v", aaaaResp.Answer)
	}
	if got := aaaaResp.Answer[0].(*dns.AAAA).AAAA.String(); got != targetIP {
		t.Fatalf("expected round-trip AAAA %s, got %s", targetIP, got)
	}
}

func TestLightupForwardExactExcludedAddressRejected(t *testing.T) {
	cfg := forwardTemplateLightupConfig()
	config.SetupDefaults(cfg)
	addr, _ := startRecordServer(t, cfg, nil)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("addr-2001-0db8-5353-0000-0000-0000-0000-0001.example.org.", dns.TypeAAAA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for excluded exact address, got %d answer=%v", r.Rcode, r.Answer)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected no AAAA answer for excluded exact address, got %v", r.Answer)
	}
}

func TestLightupForwardExactOutsidePrefixRejected(t *testing.T) {
	cfg := forwardTemplateLightupConfig()
	config.SetupDefaults(cfg)
	addr, _ := startRecordServer(t, cfg, nil)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("addr-2001-0db8-9999-0000-0000-0000-0000-0111.example.org.", dns.TypeAAAA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for outside-prefix exact address, got %d answer=%v", r.Rcode, r.Answer)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected no AAAA answer for outside-prefix exact address, got %v", r.Answer)
	}
}

func TestLightupForwardExactExplicitAAAABeatsTemplate(t *testing.T) {
	cfg := forwardTemplateLightupConfig()
	cfg.Zones[0].Serve = "secondary"
	cfg.Zones[0].Masters = nil
	config.SetupDefaults(cfg)
	addr, auth := startRecordServer(t, cfg, nil)

	owner := "addr-2001-0db8-5353-0000-0000-0000-0000-0111.example.org."
	explicit := &dns.AAAA{Hdr: hdr(owner, dns.TypeAAAA, cfg.Zones[0].TTLAnswer), AAAA: net.ParseIP("2001:db8::beef")}
	auth.mu.Lock()
	auth.records = map[string][]dns.RR{strings.ToLower(owner): {explicit}}
	auth.axfrRRs = []dns.RR{explicit}
	auth.zidx = buildIndexFromRRs(cfg.Zones[0].Name, []dns.RR{explicit})
	auth.mu.Unlock()

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion(owner, dns.TypeAAAA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("AAAA query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected one explicit AAAA answer, got %v", r.Answer)
	}
	if got := r.Answer[0].(*dns.AAAA).AAAA.String(); got != "2001:db8::beef" {
		t.Fatalf("expected explicit AAAA to win, got %s", got)
	}
}

func TestLightupForwardTemplateRejectsArbitraryNames(t *testing.T) {
	cfg := forwardTemplateLightupConfig()
	config.SetupDefaults(cfg)
	addr, _ := startRecordServer(t, cfg, nil)

	c := &dns.Client{Net: "tcp"}
	for _, qname := range []string{
		"trash.example.org.",
		"totallyinvalidname.example.org.",
	} {
		m := new(dns.Msg)
		m.SetQuestion(qname, dns.TypeAAAA)
		r, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("AAAA query %s: %v", qname, err)
		}
		if r.Rcode != dns.RcodeNameError {
			t.Fatalf("expected NXDOMAIN for %s, got rcode=%d answer=%v", qname, r.Rcode, r.Answer)
		}
		if len(r.Answer) != 0 {
			t.Fatalf("expected no AAAA answer for %s, got %v", qname, r.Answer)
		}
	}
}

func TestLightupPrivateIPv4ExactRoundTripSymmetry(t *testing.T) {
	cfg := forwardReverseDualStackLightupConfig()
	cfg.Zones[0].Lightup.ForwardTemplate = "templated-{addr}.example.org."
	addr, _ := startZonesServer(t, cfg)

	targetIP := "172.16.0.42"
	c := &dns.Client{Net: "tcp"}

	ptrQ := new(dns.Msg)
	ptrQ.SetQuestion(reverseOwnerForIP(t, targetIP), dns.TypePTR)
	ptrResp, _, err := c.Exchange(ptrQ, addr)
	if err != nil {
		t.Fatalf("PTR query: %v", err)
	}
	if len(ptrResp.Answer) != 1 {
		t.Fatalf("expected one PTR answer, got %v", ptrResp.Answer)
	}
	ptrName := ptrResp.Answer[0].(*dns.PTR).Ptr
	wantPTR := "templated-172-16-0-42.example.org."
	if ptrName != wantPTR {
		t.Fatalf("expected PTR target %s, got %s", wantPTR, ptrName)
	}

	aQ := new(dns.Msg)
	aQ.SetQuestion(ptrName, dns.TypeA)
	aResp, _, err := c.Exchange(aQ, addr)
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	if len(aResp.Answer) != 1 {
		t.Fatalf("expected one A answer, got %v", aResp.Answer)
	}
	if got := aResp.Answer[0].(*dns.A).A.String(); got != targetIP {
		t.Fatalf("expected round-trip A %s, got %s", targetIP, got)
	}
}

func TestLightupPrivateIPv4ExcludedAddressRejected(t *testing.T) {
	cfg := forwardReverseDualStackLightupConfig()
	cfg.Zones[0].Lightup.ForwardTemplate = "templated-{addr}.example.org."
	addr, _ := startRecordServer(t, cfg, nil)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("templated-172-16-0-1.example.org.", dns.TypeA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for excluded exact IPv4 address, got %d answer=%v", r.Rcode, r.Answer)
	}
}

func TestLightupPrivateIPv4TemplateRejectsArbitraryNames(t *testing.T) {
	cfg := forwardReverseDualStackLightupConfig()
	cfg.Zones[0].Lightup.ForwardTemplate = "templated-{addr}.example.org."
	addr, _ := startRecordServer(t, cfg, nil)

	c := &dns.Client{Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion("trash.example.org.", dns.TypeA)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for arbitrary IPv4 template miss, got %d answer=%v", r.Rcode, r.Answer)
	}
}

func stringsHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
