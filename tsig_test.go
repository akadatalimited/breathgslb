package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// axfrTestRecords returns a small zone for transfer.
func axfrTestRecords() []dns.RR {
	soa, _ := dns.NewRR("example.org. 3600 IN SOA ns.example.org. hostmaster.example.org. 1 3600 900 604800 86400")
	a, _ := dns.NewRR("example.org. 3600 IN A 192.0.2.1")
	// A zone transfer requires the SOA to appear at the beginning and end.
	return []dns.RR{soa, a, soa}
}

func TestTSIGKeyGenerationAndAXFR(t *testing.T) {
	tmpDir := t.TempDir()
	seedEnv := "TSIG_TEST_SEED"
	seedVal := "deterministic-seed"
	t.Setenv(seedEnv, seedVal)

	cfg := &Config{
		TSIG: &TSIGGlobalConfig{Path: tmpDir},
		Zones: []Zone{
			{
				Name: "example.org.",
				TSIG: &TSIGZoneConfig{
					SeedEnv: seedEnv,
					Keys:    []TSIGKey{{Name: "axfr-key."}},
				},
			},
		},
	}

	generateTSIGKeys(cfg)

	key := cfg.Zones[0].TSIG.Keys[0]
	expected := deriveTSIGSecret(seedVal, key.Name, 0)
	if key.Algorithm != "hmac-sha256" {
		t.Fatalf("expected algorithm hmac-sha256, got %s", key.Algorithm)
	}
	if key.Secret != expected {
		t.Fatalf("unexpected secret: %s", key.Secret)
	}

	// verify key file
	keyFile := filepath.Join(tmpDir, "axfr-key.key")
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, key.Algorithm) || !strings.Contains(content, key.Secret) {
		t.Fatalf("key file missing algorithm or secret: %s", content)
	}

	// set up AXFR server
	records := axfrTestRecords()
	dns.HandleFunc("example.org.", func(w dns.ResponseWriter, r *dns.Msg) {
		ch := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		go tr.Out(w, r, ch)
		ch <- &dns.Envelope{RR: records}
		close(ch)
		w.Hijack()
	})
	defer dns.HandleRemove("example.org.")

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{Listener: l, TsigSecret: map[string]string{key.Name: key.Secret}}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() {
		_ = srv.ActivateAndServe()
	}()
	defer srv.Shutdown()
	<-started

	// perform transfer
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{key.Name: key.Secret}
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig(key.Name, dns.HmacSHA256, 300, time.Now().Unix())

	env, err := tr.In(m, l.Addr().String())
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}

	var got []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("transfer error: %v", e.Error)
		}
		got = append(got, e.RR...)
	}
	if len(got) != len(records) {
		t.Fatalf("expected %d records, got %d", len(records), len(got))
	}
	for i, rr := range records {
		if dns.IsDuplicate(got[i], rr) {
			continue
		}
		t.Fatalf("record %d mismatch: got %v want %v", i, got[i], rr)
	}
}
