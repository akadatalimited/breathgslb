package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	cfgpkg "github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func replicaTestConfig(root, serve string, masters []string) *Config {
	return &Config{
		TSIG: &TSIGGlobalConfig{Path: filepath.Join(root, "tsig")},
		Zones: []Zone{{
			Name:       "example.org.",
			NS:         []string{"ns1.example.org.", "ns2.example.org."},
			Admin:      "hostmaster.example.org.",
			TTLSOA:     3600,
			TTLAnswer:  300,
			Refresh:    60,
			Retry:      30,
			Expire:     600,
			Minttl:     60,
			Serve:      serve,
			Masters:    masters,
			AAAAMaster: []IPAddr{{IP: "2001:db8::1"}},
			AMaster:    []IPAddr{{IP: "192.0.2.1"}},
			TXT:        []TXTRecord{{Text: []string{"replica"}}},
			DNSSEC: &DNSSECZoneConfig{
				Mode:            DNSSECModeGenerated,
				ZSKFile:         filepath.Join(root, "keys", "example.org.zsk"),
				KSKFile:         filepath.Join(root, "keys", "example.org.ksk"),
				NSEC3Iterations: 0,
			},
			TSIG: &TSIGZoneConfig{
				DefaultAlgorithm: "hmac-sha256",
				Keys: []TSIGKey{{
					Name:         "axfr-key.",
					Secret:       "",
					AllowXFRFrom: []string{"127.0.0.1"},
				}},
			},
		}},
	}
}

func prepareReplicaConfig(t *testing.T, cfg *Config) {
	t.Helper()
	if err := os.MkdirAll(cfg.TSIG.Path, 0o755); err != nil {
		t.Fatalf("mkdir tsig: %v", err)
	}
	for _, z := range cfg.Zones {
		if z.DNSSEC != nil {
			if err := os.MkdirAll(filepath.Dir(z.DNSSEC.ZSKFile), 0o755); err != nil {
				t.Fatalf("mkdir keys: %v", err)
			}
		}
	}
	cfgpkg.SetupDefaults(cfg)
	cfgpkg.GenerateTSIGKeys(cfg)
}

func TestReplicaSyncRestoresSignedServing(t *testing.T) {
	ensureIPv4(t)
	primaryRoot := filepath.Join(t.TempDir(), "primary")
	secondaryRoot := filepath.Join(t.TempDir(), "secondary")
	if err := os.MkdirAll(filepath.Join(primaryRoot, "serials"), 0o755); err != nil {
		t.Fatalf("mkdir primary serials: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(secondaryRoot, "serials"), 0o755); err != nil {
		t.Fatalf("mkdir secondary serials: %v", err)
	}

	oldSerialDir := serialDir
	serialDir = filepath.Join(primaryRoot, "serials")
	t.Cleanup(func() { serialDir = oldSerialDir })

	primaryCfg := replicaTestConfig(primaryRoot, "primary", nil)
	prepareReplicaConfig(t, primaryCfg)
	_, primaryAddr, primaryAuth := startTestServer(t, primaryCfg, collectTSIGSecrets(primaryCfg), nil)
	primaryAuth.setMasterUp(true, true)
	primaryAuth.cancel()

	secondaryCfg := replicaTestConfig(secondaryRoot, "secondary", nil)
	prepareReplicaConfig(t, secondaryCfg)
	_, _, secondaryAuth := startTestServer(t, secondaryCfg, collectTSIGSecrets(secondaryCfg), nil)
	secondaryAuth.zone.Masters = []string{primaryAddr}
	if err := secondaryAuth.transferFromMasters(); err == nil {
		t.Fatalf("expected AXFR to fail before tsig state sync")
	}

	check := exec.Command("sh", "../scripts/slavesync", "--check", primaryRoot, secondaryRoot)
	check.Dir = "."
	if err := check.Run(); err == nil {
		t.Fatalf("expected sync check to fail before state sync")
	}

	syncCmd := exec.Command("sh", "../scripts/slavesync", primaryRoot, secondaryRoot)
	syncCmd.Dir = "."
	if out, err := syncCmd.CombinedOutput(); err != nil {
		t.Fatalf("slavesync failed: %v\n%s", err, out)
	}
	check = exec.Command("sh", "../scripts/slavesync", "--check", primaryRoot, secondaryRoot)
	check.Dir = "."
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("sync check after copy failed: %v\n%s", err, out)
	}

	secondaryCfg = replicaTestConfig(secondaryRoot, "secondary", nil)
	prepareReplicaConfig(t, secondaryCfg)
	_, secondaryAddr, secondaryAuth := startTestServer(t, secondaryCfg, collectTSIGSecrets(secondaryCfg), nil)
	secondaryAuth.zone.Masters = []string{primaryAddr}
	if err := secondaryAuth.transferFromMasters(); err != nil {
		t.Fatalf("transfer after sync: %v", err)
	}

	c := &dns.Client{Net: "tcp"}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetDo()

	query := new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeAAAA)
	query.Extra = append(query.Extra, opt)

	primaryResp, _, err := c.Exchange(query, primaryAddr)
	if err != nil {
		t.Fatalf("query primary: %v", err)
	}
	secondaryResp, _, err := c.Exchange(query, secondaryAddr)
	if err != nil {
		t.Fatalf("query secondary: %v", err)
	}

	toStrings := func(rrs []dns.RR) []string {
		out := make([]string, 0, len(rrs))
		for _, rr := range rrs {
			out = append(out, rr.String())
		}
		sort.Strings(out)
		return out
	}

	gotPrimary := toStrings(primaryResp.Answer)
	gotSecondary := toStrings(secondaryResp.Answer)
	if strings.Join(gotPrimary, "\n") != strings.Join(gotSecondary, "\n") {
		t.Fatalf("signed answer mismatch\nprimary:\n%s\nsecondary:\n%s", strings.Join(gotPrimary, "\n"), strings.Join(gotSecondary, "\n"))
	}

	query = new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeA)
	query.Extra = append(query.Extra, opt)
	primaryResp, _, err = c.Exchange(query, primaryAddr)
	if err != nil {
		t.Fatalf("query primary A: %v", err)
	}
	secondaryResp, _, err = c.Exchange(query, secondaryAddr)
	if err != nil {
		t.Fatalf("query secondary A: %v", err)
	}
	gotPrimary = toStrings(primaryResp.Answer)
	gotSecondary = toStrings(secondaryResp.Answer)
	if strings.Join(gotPrimary, "\n") != strings.Join(gotSecondary, "\n") {
		t.Fatalf("signed A answer mismatch\nprimary:\n%s\nsecondary:\n%s", strings.Join(gotPrimary, "\n"), strings.Join(gotSecondary, "\n"))
	}
}
