package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTestServer(t *testing.T, cfg *Config, secrets map[string]string, prev map[string]*authority) (*dns.Server, string, *authority) {
	t.Helper()
	ensureIPv4(t)
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

type recordingProvider struct {
	secret string
	macs   []string
}

func (p *recordingProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(p.secret)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, raw)
	h.Write(msg)
	return h.Sum(nil), nil
}

func (p *recordingProvider) Verify(msg []byte, t *dns.TSIG) error {
	p.macs = append(p.macs, t.MAC)
	exp, err := p.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(exp, mac) {
		return dns.ErrSig
	}
	return nil
}

func TestAXFRUnsignedAllowedAndSigned(t *testing.T) {
	ensureIPv4(t)
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{AllowUnsigned: true, Keys: []TSIGKey{{Name: "axfr-key.", Secret: testSecret, AllowXFRFrom: []string{"127.0.0.1"}}}},
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

func TestAXFRUnsignedRejected(t *testing.T) {
	ensureIPv4(t)
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{Keys: []TSIGKey{{Name: "axfr-key.", Secret: testSecret, AllowXFRFrom: []string{"127.0.0.1"}}}},
	}}}
	_, addr, _ := startTestServer(t, cfg, map[string]string{"axfr-key.": testSecret}, nil)

	tr := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("transfer setup: %v", err)
	}
	e, ok := <-env
	if !ok {
		t.Fatalf("no response received")
	}
	if e.Error == nil || !strings.Contains(e.Error.Error(), "bad xfr rcode") {
		t.Fatalf("expected transfer refusal, got %v", e.Error)
	}
	if _, ok := <-env; ok {
		t.Fatalf("expected channel to close after error")
	}
}

func TestAXFRWrongKey(t *testing.T) {
	ensureIPv4(t)
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
	ensureIPv4(t)
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
	e, ok := <-env
	if !ok {
		t.Fatalf("no response received")
	}
	// "bad xfr rcode" indicates the AXFR request was refused because the
	// client's IP is not in the allow list.
	if e.Error == nil || !strings.Contains(e.Error.Error(), "bad xfr rcode") {
		t.Fatalf("expected transfer refusal, got %v", e.Error)
	}
	// After an error, the transfer channel should close without sending any
	// further records.
	if _, ok := <-env; ok {
		t.Fatalf("expected channel to close after error")
	}
}

func TestAXFRTSIGMACNonZero(t *testing.T) {
	ensureIPv4(t)
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{Keys: []TSIGKey{{Name: "axfr-key.", Secret: testSecret, AllowXFRFrom: []string{"127.0.0.1"}}}},
	}}}
	_, addr, _ := startTestServer(t, cfg, map[string]string{"axfr-key.": testSecret}, nil)

	prov := &recordingProvider{secret: testSecret}
	tr := new(dns.Transfer)
	tr.TsigProvider = prov
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig("axfr-key.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	for e := range env {
		if e.Error != nil {
			t.Fatalf("transfer error: %v", e.Error)
		}
	}
	if len(prov.macs) == 0 || prov.macs[len(prov.macs)-1] == "" {
		t.Fatalf("expected TSIG MAC")
	}
}

func TestAXFRMACChaining(t *testing.T) {
	ensureIPv4(t)
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{Keys: []TSIGKey{{Name: "axfr-key.", Secret: testSecret, AllowXFRFrom: []string{"127.0.0.1"}}}},
	}}}
	_, addr, _ := startTestServer(t, cfg, map[string]string{"axfr-key.": testSecret}, nil)

	prov := &recordingProvider{secret: testSecret}
	tr := new(dns.Transfer)
	tr.TsigProvider = prov
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig("axfr-key.", dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	for e := range env {
		if e.Error != nil {
			t.Fatalf("transfer error: %v", e.Error)
		}
	}
	if len(prov.macs) < 3 {
		t.Fatalf("expected multiple TSIG MACs, got %d", len(prov.macs))
	}
	if prov.macs[0] == prov.macs[1] {
		t.Fatalf("expected distinct MACs across messages")
	}
	for i, mac := range prov.macs[:3] {
		if mac == "" {
			t.Fatalf("mac %d empty", i)
		}
	}
}
