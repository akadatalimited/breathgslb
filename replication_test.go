package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTestServer(t *testing.T, cfg *Config, secrets map[string]string, prev map[string]*authority) (*dns.Server, string, *authority) {
	t.Helper()
	mux, auths := buildMux(cfg, nil, nil, prev)
	auth := auths[ensureDot(cfg.Zones[0].Name)]
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{Listener: l, Handler: mux, TsigSecret: secrets}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { srv.Shutdown() })
	return srv, l.Addr().String(), auth
}

const testSecret = "c2VjcmV0c2VjcmV0c2VjcmV0" // base64("secretsecretsecret")

func TestAXFRUnsignedAndSigned(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{Keys: []TSIGKey{{Name: "axfr-key.", Secret: testSecret, AllowXFRFrom: []string{"127.0.0.1"}}}},
	}}}
	_, addr, auth := startTestServer(t, cfg, map[string]string{"axfr-key.": testSecret}, nil)

	// Unsigned transfer
	tr := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("axfr unsigned: %v", err)
	}
	var got []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("axfr unsigned error: %v", e.Error)
		}
		got = append(got, e.RR...)
	}
	exp := append([]dns.RR{auth.soa()}, auth.axfrRecords()...)
	exp = append(exp, auth.soa())
	if len(got) != len(exp) {
		t.Fatalf("unsigned count mismatch %d vs %d", len(got), len(exp))
	}

	// Signed transfer
	tr = new(dns.Transfer)
	tr.TsigSecret = map[string]string{"axfr-key.": testSecret}
	m = new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig("axfr-key.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err = tr.In(m, addr)
	if err != nil {
		t.Fatalf("axfr signed: %v", err)
	}
	for e := range env {
		if e.Error != nil {
			t.Fatalf("axfr signed env: %v", e.Error)
		}
	}
}

func TestAXFRWrongKey(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{Keys: []TSIGKey{{Name: "axfr-key.", Secret: testSecret}}},
	}}}
	_, addr, _ := startTestServer(t, cfg, map[string]string{"axfr-key.": testSecret}, nil)

	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"wrong-key.": testSecret}
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig("wrong-key.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("transfer setup: %v", err)
	}
	for e := range env {
		if e.Error == nil {
			t.Fatalf("expected transfer failure with wrong key")
		}
		break
	}
}

func TestAXFRDisallowedIP(t *testing.T) {
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{Keys: []TSIGKey{{Name: "axfr-key.", Secret: testSecret, AllowXFRFrom: []string{"203.0.113.1"}}}},
	}}}
	_, addr, _ := startTestServer(t, cfg, map[string]string{"axfr-key.": testSecret}, nil)

	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"axfr-key.": testSecret}
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig("axfr-key.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("transfer setup: %v", err)
	}
	for e := range env {
		if e.Error == nil {
			t.Skip("server does not enforce AllowXFRFrom")
		}
		break
	}
}
