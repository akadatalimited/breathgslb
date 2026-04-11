package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func startTestServerV6(t *testing.T, cfg *Config) (*dns.Server, string) {
	t.Helper()
	ensureIPv6(t)
	oldDisable := cfg.DisableBackgroundLoops
	cfg.DisableBackgroundLoops = true
	t.Cleanup(func() { cfg.DisableBackgroundLoops = oldDisable })
	mux, auths := buildMux(cfg, nil, nil, nil)
	l, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("listen tcp6: %v", err)
	}
	srv := &dns.Server{Listener: l, Handler: mux, TsigSecret: collectTSIGSecrets(cfg)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	for _, auth := range auths {
		if auth != nil && auth.cancel != nil {
			t.Cleanup(auth.cancel)
		}
	}
	return srv, l.Addr().String()
}

func startTestServerV6Handler(t *testing.T, h dns.Handler, secrets map[string]string) (*dns.Server, string) {
	t.Helper()
	ensureIPv6(t)
	l, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("listen tcp6: %v", err)
	}
	srv := &dns.Server{Listener: l, Handler: h, TsigSecret: secrets}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return srv, l.Addr().String()
}

func TestDiscoveryBootstrapCreatesSecondaryZonesFromCatalog(t *testing.T) {
	ensureIPv6(t)
	primary := &Config{
		TimeoutSec: 1,
		Discovery: &DiscoveryConfig{
			CatalogZone: "_catalog.breathgslb.",
			TSIG: &TSIGZoneConfig{Keys: []TSIGKey{{
				Name:         "cluster-xfr.",
				Algorithm:    "hmac-sha256",
				Secret:       testSecret,
				AllowXFRFrom: []string{"::1"},
			}}},
		},
		Zones: []Zone{
			{
				Name:      "lightitup.zerodns.co.uk.",
				NS:        []string{"gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."},
				Admin:     "hostmaster.zerodns.co.uk.",
				TTLSOA:    60,
				TTLAnswer: 20,
				Refresh:   60,
				Retry:     10,
				Expire:    90,
				Minttl:    60,
				AAAAMaster: []IPAddr{
					{IP: "2a02:8012:bc57:5353::1"},
				},
			},
			{
				Name:      "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.",
				NS:        []string{"gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."},
				Admin:     "hostmaster.zerodns.co.uk.",
				TTLSOA:    60,
				TTLAnswer: 20,
				Refresh:   60,
				Retry:     10,
				Expire:    90,
				Minttl:    60,
				PTR: []PTRRecord{{
					Name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
					PTR:  "gslb.zerodns.co.uk.",
				}},
			},
		},
	}
	appendCatalogZone(primary)
	_, addr := startTestServerV6(t, primary)

	secondary := &Config{
		TimeoutSec: 1,
		Discovery: &DiscoveryConfig{
			CatalogZone: "_catalog.breathgslb.",
			Masters:     []string{addr},
			TSIG: &TSIGZoneConfig{Keys: []TSIGKey{{
				Name:      "cluster-xfr.",
				Algorithm: "hmac-sha256",
				Secret:    testSecret,
			}}},
		},
	}
	if err := bootstrapDiscoveredZones(secondary); err != nil {
		t.Fatalf("bootstrapDiscoveredZones: %v", err)
	}
	if len(secondary.Zones) != 2 {
		t.Fatalf("expected 2 discovered zones, got %d", len(secondary.Zones))
	}
	gotNames := []string{secondary.Zones[0].Name, secondary.Zones[1].Name}
	sort.Strings(gotNames)
	wantNames := []string{"3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.", "lightitup.zerodns.co.uk."}
	if len(gotNames) != len(wantNames) || gotNames[0] != wantNames[0] || gotNames[1] != wantNames[1] {
		t.Fatalf("discovered zones = %v want %v", gotNames, wantNames)
	}
	for _, z := range secondary.Zones {
		if z.Serve != "secondary" {
			t.Fatalf("%s serve=%q want secondary", z.Name, z.Serve)
		}
		if len(z.Masters) != 1 || z.Masters[0] != addr {
			t.Fatalf("%s masters=%v want [%s]", z.Name, z.Masters, addr)
		}
		if z.TSIG == nil || len(z.TSIG.Keys) != 1 || z.TSIG.Keys[0].Name != "cluster-xfr." {
			t.Fatalf("%s tsig=%#v", z.Name, z.TSIG)
		}
	}

	for _, z := range secondary.Zones {
		auth := &authority{
			ctx:   context.Background(),
			cfg:   secondary,
			zone:  z,
			state: &state{},
		}
		if err := auth.transferFromMasters(); err != nil {
			t.Fatalf("%s transferFromMasters: %v", z.Name, err)
		}
		if auth.soaRR == nil {
			t.Fatalf("%s: expected SOA after transfer", z.Name)
		}
	}
}

func TestSecondaryDiscoverySeesNewReverseZoneAfterPrimaryReload(t *testing.T) {
	ensureIPv6(t)

	primaryDir := t.TempDir()
	secondaryDir := t.TempDir()
	primaryZones := filepath.Join(primaryDir, "zones")
	primaryReverse := filepath.Join(primaryDir, "reverse")
	if err := os.MkdirAll(primaryZones, 0o755); err != nil {
		t.Fatalf("mkdir zones: %v", err)
	}
	if err := os.MkdirAll(primaryReverse, 0o755); err != nil {
		t.Fatalf("mkdir reverse: %v", err)
	}

	primaryCfgPath := filepath.Join(primaryDir, "config.yaml")
	primaryCfgYAML := strings.TrimSpace(`
timeout_sec: 1
interval_sec: 1
zones_dir: "` + primaryZones + `"
reverse_dir: "` + primaryReverse + `"
zones: []
discovery:
  catalog_zone: "_catalog.breathgslb."
  tsig:
    keys:
      - name: "cluster-xfr."
        algorithm: "hmac-sha256"
        secret: "` + testSecret + `"
        allow_xfr_from:
          - "::1"
`) + "\n"
	if err := os.WriteFile(primaryCfgPath, []byte(primaryCfgYAML), 0o644); err != nil {
		t.Fatalf("write primary config: %v", err)
	}

	forwardPath := filepath.Join(primaryZones, "lightitup.zerodns.co.uk.fwd.yaml")
	forwardZoneYAML := strings.TrimSpace(`
- name: "lightitup.zerodns.co.uk."
  serve: "primary"
  ns: ["gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."]
  admin: "hostmaster.zerodns.co.uk."
  ttl_soa: 60
  ttl_answer: 20
  refresh: 60
  retry: 10
  expire: 90
  minttl: 60
  aaaa_master:
    - ip: "2a02:8012:bc57:5353::1"
`) + "\n"
	if err := os.WriteFile(forwardPath, []byte(forwardZoneYAML), 0o644); err != nil {
		t.Fatalf("write forward zone: %v", err)
	}

	primaryCfg, _, err := loadRuntimeConfig(primaryCfgPath)
	if err != nil {
		t.Fatalf("load primary runtime: %v", err)
	}
	primaryCfg.DisableBackgroundLoops = true
	primaryMux, primaryAuths := buildMux(primaryCfg, nil, nil, nil)
	rt := &router{}
	rt.inner.Store(primaryMux)
	_, addr := startTestServerV6Handler(t, rt, collectTSIGSecrets(primaryCfg))
	for _, auth := range primaryAuths {
		if auth != nil && auth.cancel != nil {
			defer auth.cancel()
		}
	}

	secondaryCfgPath := filepath.Join(secondaryDir, "config.gslb2.yaml")
	secondaryCfgYAML := strings.TrimSpace(`
timeout_sec: 1
interval_sec: 1
zones: []
discovery:
  catalog_zone: "_catalog.breathgslb."
  masters: ["` + addr + `"]
  tsig:
    keys:
      - name: "cluster-xfr."
        algorithm: "hmac-sha256"
        secret: "` + testSecret + `"
`) + "\n"
	if err := os.WriteFile(secondaryCfgPath, []byte(secondaryCfgYAML), 0o644); err != nil {
		t.Fatalf("write secondary config: %v", err)
	}

	secondaryCfg, _, err := loadRuntimeConfig(secondaryCfgPath)
	if err != nil {
		t.Fatalf("load secondary runtime: %v", err)
	}
	if len(secondaryCfg.Zones) != 1 || !strings.EqualFold(secondaryCfg.Zones[0].Name, "lightitup.zerodns.co.uk.") {
		t.Fatalf("initial discovered zones = %#v", secondaryCfg.Zones)
	}

	reversePath := filepath.Join(primaryReverse, "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.rev.yaml")
	reverseZoneYAML := strings.TrimSpace(`
- name: "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa."
  serve: "primary"
  ns: ["gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."]
  admin: "hostmaster.zerodns.co.uk."
  ttl_soa: 60
  ttl_answer: 20
  refresh: 60
  retry: 10
  expire: 90
  minttl: 60
  ptr:
    - name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
      ptr: "gslb.zerodns.co.uk."
`) + "\n"
	if err := os.WriteFile(reversePath, []byte(reverseZoneYAML), 0o644); err != nil {
		t.Fatalf("write reverse zone: %v", err)
	}

	primaryCfg2, _, err := loadRuntimeConfig(primaryCfgPath)
	if err != nil {
		t.Fatalf("reload primary runtime: %v", err)
	}
	primaryCfg2.DisableBackgroundLoops = true
	primaryMux2, primaryAuths2 := buildMux(primaryCfg2, nil, nil, primaryAuths)
	rt.inner.Store(primaryMux2)
	for _, auth := range primaryAuths {
		if auth != nil && auth.cancel != nil {
			auth.cancel()
		}
	}
	for _, auth := range primaryAuths2 {
		if auth != nil && auth.cancel != nil {
			defer auth.cancel()
		}
	}

	secondaryCfg2, _, err := loadRuntimeConfig(secondaryCfgPath)
	if err != nil {
		t.Fatalf("reload secondary runtime: %v", err)
	}
	found := false
	for _, z := range secondaryCfg2.Zones {
		if strings.EqualFold(z.Name, "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.") {
			found = true
			auth := &authority{
				ctx:   context.Background(),
				cfg:   secondaryCfg2,
				zone:  z,
				state: &state{},
			}
			if err := auth.transferFromMasters(); err != nil {
				t.Fatalf("%s transferFromMasters: %v", z.Name, err)
			}
			if auth.soaRR == nil {
				t.Fatalf("%s: expected SOA after transfer", z.Name)
			}
		}
	}
	if !found {
		t.Fatalf("secondary did not discover new reverse zone: %#v", secondaryCfg2.Zones)
	}
}
