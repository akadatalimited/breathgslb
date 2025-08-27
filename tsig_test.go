package main

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akadatalimited/breathgslb/config"
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
					Keys: []TSIGKey{
						{Name: "axfr-256.", Algorithm: "hmac-sha256"},
						{Name: "axfr-512.", Algorithm: "hmac-sha512"},
					},
				},
			},
		},
	}

	config.GenerateTSIGKeys(cfg)

	algConst := map[string]string{"hmac-sha256": dns.HmacSHA256, "hmac-sha512": dns.HmacSHA512}

	for _, key := range cfg.Zones[0].TSIG.Keys {
		expected := config.DeriveTSIGSecret(seedVal, key.Name, 0)
		if key.Secret != expected {
			t.Fatalf("unexpected secret for %s: %s", key.Name, key.Secret)
		}
		keyFile := filepath.Join(tmpDir, strings.TrimSuffix(key.Name, ".")+".key")
		data, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatalf("reading key file: %v", err)
		}
		content := string(data)
		if !strings.Contains(content, key.Algorithm) || !strings.Contains(content, key.Secret) {
			t.Fatalf("key file missing algorithm or secret: %s", content)
		}

		k := key // capture for subtest
		t.Run(k.Algorithm, func(t *testing.T) {
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
			srv := &dns.Server{Listener: l, TsigSecret: map[string]string{k.Name: k.Secret}}
			started := make(chan struct{})
			srv.NotifyStartedFunc = func() { close(started) }
			go func() { _ = srv.ActivateAndServe() }()
			t.Cleanup(func() { srv.Shutdown() })
			<-started

			tr := new(dns.Transfer)
			tr.TsigSecret = map[string]string{k.Name: k.Secret}
			m := new(dns.Msg)
			m.SetAxfr("example.org.")
			m.SetTsig(k.Name, algConst[k.Algorithm], 300, time.Now().Unix())

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
		})
	}
}

func TestTSIGMissingSeedEnv(t *testing.T) {
	cfgA := &Config{TSIG: &TSIGGlobalConfig{}, Zones: []Zone{{Name: "example.org.", TSIG: &TSIGZoneConfig{SeedEnv: "MISSING_ENV", Keys: []TSIGKey{{Name: "a."}}}}}}
	cfgB := &Config{TSIG: &TSIGGlobalConfig{}, Zones: []Zone{{Name: "example.org.", TSIG: &TSIGZoneConfig{SeedEnv: "MISSING_ENV", Keys: []TSIGKey{{Name: "a."}}}}}}
	config.GenerateTSIGKeys(cfgA)
	config.GenerateTSIGKeys(cfgB)
	if cfgA.Zones[0].TSIG.Keys[0].Secret == cfgB.Zones[0].TSIG.Keys[0].Secret {
		t.Fatalf("expected random secrets when seed env missing")
	}
}

func TestTSIGInvalidAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	seedEnv := "TSIG_TEST_SEED_BADALG"
	seedVal := "deterministic-seed"
	t.Setenv(seedEnv, seedVal)

	cfg := &Config{
		TSIG: &TSIGGlobalConfig{Path: tmpDir},
		Zones: []Zone{{
			Name: "example.org.",
			TSIG: &TSIGZoneConfig{
				SeedEnv: seedEnv,
				Keys:    []TSIGKey{{Name: "badalg.", Algorithm: "bad-alg"}},
			},
		}},
	}

	config.GenerateTSIGKeys(cfg)

	key := cfg.Zones[0].TSIG.Keys[0]
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
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { srv.Shutdown() })

	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{key.Name: key.Secret}
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig(key.Name, key.Algorithm, 300, time.Now().Unix())

	_, err = tr.In(m, l.Addr().String())
	if err == nil {
		t.Fatalf("expected failure with invalid algorithm")
	}
}

func TestTSIGDuplicateKeyNames(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		TSIG: &TSIGGlobalConfig{Path: tmpDir},
		Zones: []Zone{{
			Name: "example.org.",
			TSIG: &TSIGZoneConfig{Keys: []TSIGKey{
				{Name: "dup-key.", Secret: base64.StdEncoding.EncodeToString([]byte("secret1"))},
				{Name: "dup-key.", Secret: base64.StdEncoding.EncodeToString([]byte("secret2"))},
			}},
		}},
	}

	config.GenerateTSIGKeys(cfg)

	keys := cfg.Zones[0].TSIG.Keys
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
	// Server holds the second key's secret
	srv := &dns.Server{Listener: l, TsigSecret: map[string]string{keys[1].Name: keys[1].Secret}}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { srv.Shutdown() })

	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{keys[0].Name: keys[0].Secret}
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig(keys[0].Name, dns.HmacSHA256, 300, time.Now().Unix())

	env, err := tr.In(m, l.Addr().String())
	if err == nil {
		for e := range env {
			if e.Error == nil {
				t.Fatalf("expected failure due to duplicate key names")
			}
			break
		}
	}
}

func TestTSIGAllowXFRFromRestriction(t *testing.T) {
	seedEnv := "TSIG_SEED_ALLOW"
	seedVal := "deterministic-seed"
	t.Setenv(seedEnv, seedVal)
	cfg := &Config{Zones: []Zone{{
		Name:      "example.org.",
		NS:        []string{"ns.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    3600,
		TTLAnswer: 300,
		AMaster:   []IPAddr{{IP: "192.0.2.1"}},
		TSIG:      &TSIGZoneConfig{SeedEnv: seedEnv, Keys: []TSIGKey{{Name: "xfr-key.", AllowXFRFrom: []string{"203.0.113.1"}}}},
	}}}

	config.GenerateTSIGKeys(cfg)
	key := cfg.Zones[0].TSIG.Keys[0]

	srv, addr, _ := startTestServer(t, cfg, map[string]string{key.Name: key.Secret}, nil)
	defer srv.Shutdown()

	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{key.Name: key.Secret}
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig(key.Name, dns.HmacSHA256, 300, time.Now().Unix())
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
}
