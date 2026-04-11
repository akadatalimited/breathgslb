package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configpkg "github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

func TestSecondaryTransferPersistsForwardSnapshotAndSerial(t *testing.T) {
	ensureIPv6(t)
	root := t.TempDir()
	oldSerialDir := serialDir
	serialDir = filepath.Join(root, "serials")
	t.Cleanup(func() { serialDir = oldSerialDir })

	primary := &Config{
		BaseDir:    root,
		TimeoutSec: 1,
		Zones: []Zone{{
			Name:      "example.org.",
			NS:        []string{"ns1.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    60,
			TTLAnswer: 20,
			Refresh:   60,
			Retry:     10,
			Expire:    90,
			Minttl:    60,
			AAAAMaster: []IPAddr{
				{IP: "2001:db8::10"},
			},
			Hosts: []Host{{
				Name: "app",
				Pools: []Pool{{
					Name:    "app-v6",
					Family:  "ipv6",
					Class:   "public",
					Role:    "fallback",
					Members: []IPAddr{{IP: "2001:db8::20"}},
				}},
			}},
		}},
	}
	_, addr := startTestServerV6(t, primary)

	secondaryCfg := &Config{BaseDir: root, TimeoutSec: 1}
	auth := &authority{
		ctx:   context.Background(),
		cfg:   secondaryCfg,
		zone:  Zone{Name: "example.org.", Serve: "secondary", Masters: []string{addr}},
		state: &state{},
	}
	if err := auth.transferFromMasters(); err != nil {
		t.Fatalf("transferFromMasters: %v", err)
	}

	snapPath := filepath.Join(root, "zones", "example.org.fwd.yaml")
	if _, err := os.Stat(snapPath); err != nil {
		t.Fatalf("snapshot not written: %v", err)
	}
	cfgPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("zones_dir: \""+filepath.Join(root, "zones")+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	loaded, err := configpkg.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load snapshot config: %v", err)
	}
	if len(loaded.Zones) != 1 {
		t.Fatalf("expected 1 snapshot zone, got %d", len(loaded.Zones))
	}
	z := loaded.Zones[0]
	if z.Serve != "secondary" {
		t.Fatalf("snapshot serve=%q want secondary", z.Serve)
	}
	if len(z.AAAAFallback) != 1 || z.AAAAFallback[0].IP != "2001:db8::10" {
		t.Fatalf("snapshot apex AAAA = %#v", z.AAAAFallback)
	}
	if len(z.Hosts) != 1 || z.Hosts[0].Name != "app" {
		t.Fatalf("snapshot hosts = %#v", z.Hosts)
	}
	if got := len(z.Hosts[0].Pools); got != 1 || z.Hosts[0].Pools[0].Members[0].IP != "2001:db8::20" {
		t.Fatalf("snapshot host pools = %#v", z.Hosts[0].Pools)
	}
	if _, err := os.Stat(filepath.Join(root, "serials", "example.org.serial")); err != nil {
		t.Fatalf("serial not written: %v", err)
	}
}

func TestSecondaryTransferPersistsReverseSnapshot(t *testing.T) {
	ensureIPv6(t)
	root := t.TempDir()
	oldSerialDir := serialDir
	serialDir = filepath.Join(root, "serials")
	t.Cleanup(func() { serialDir = oldSerialDir })

	zoneName := "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa."
	primary := &Config{
		BaseDir:    root,
		TimeoutSec: 1,
		Zones: []Zone{{
			Name:      zoneName,
			NS:        []string{"gslb.zerodns.co.uk."},
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
				TTL:  20,
			}},
		}},
	}
	_, addr := startTestServerV6(t, primary)

	auth := &authority{
		ctx:   context.Background(),
		cfg:   &Config{BaseDir: root, TimeoutSec: 1},
		zone:  Zone{Name: zoneName, Serve: "secondary", Masters: []string{addr}},
		state: &state{},
	}
	if err := auth.transferFromMasters(); err != nil {
		t.Fatalf("transferFromMasters: %v", err)
	}

	snapPath := filepath.Join(root, "reverse", strings.TrimSuffix(zoneName, ".")+".rev.yaml")
	if _, err := os.Stat(snapPath); err != nil {
		t.Fatalf("reverse snapshot not written: %v", err)
	}
}

func TestSecondarySnapshotPreservesRichZonePolicyModel(t *testing.T) {
	ensureIPv6(t)
	root := t.TempDir()
	oldSerialDir := serialDir
	serialDir = filepath.Join(root, "serials")
	t.Cleanup(func() { serialDir = oldSerialDir })

	z := Zone{
		Name:      "lightitup.zerodns.co.uk.",
		NS:        []string{"gslb.zerodns.co.uk.", "gslb2.zerodns.co.uk."},
		Admin:     "hostmaster.zerodns.co.uk.",
		TTLSOA:    60,
		TTLAnswer: 20,
		Refresh:   60,
		Retry:     10,
		Expire:    90,
		Minttl:    60,
		Serve:     "secondary",
		Masters:   []string{"[::1]:53"},
		Pools: []Pool{
			{Name: "public-v6-primary", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2a02:8012:bc57:5353::1"}}},
		},
		Hosts: []Host{{
			Name: "app",
			Pools: []Pool{
				{Name: "app-v6-primary", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2a02:8012:bc57:5353::10"}}},
				{Name: "app-v4-private", Family: "ipv4", Class: "private", Role: "primary", Members: []IPAddr{{IP: "172.16.0.10"}}, ClientNets: []string{"172.16.0.0/24"}},
			},
			Geo: &GeoPolicy{Named: []NamedGeoPolicy{
				{Name: "app-v6-primary", Policy: GeoTierPolicy{AllowCountries: []string{"GB"}}},
			}},
			Health: &HealthConfig{Kind: "http", HostHeader: "app.lightitup.zerodns.co.uk", Path: "/health", Scheme: "https", Port: 443, Expect: "OK"},
		}},
		Geo: &GeoPolicy{Named: []NamedGeoPolicy{
			{Name: "public-v6-primary", Policy: GeoTierPolicy{AllowCountries: []string{"GB"}, AllowContinents: []string{"EU"}}},
		}},
		Lightup: &LightupConfig{
			Enabled:         true,
			TTL:             60,
			Forward:         true,
			Reverse:         true,
			ForwardTemplate: "templated-{addr}.lightitup.zerodns.co.uk.",
			Families: []LightupFamily{{
				Family:      "ipv6",
				Class:       "public",
				Prefix:      "2a02:8012:bc57:5353::/64",
				RespondAAAA: true,
				RespondPTR:  true,
			}},
		},
		Health: &HealthConfig{Kind: "http", HostHeader: "lightitup.zerodns.co.uk", Path: "/health", Scheme: "https", Port: 443, Expect: "OK"},
	}
	soa := authSOAForTest(z, 2026041100)
	records := []dns.RR{
		&dns.AAAA{Hdr: dns.RR_Header{Name: "app.lightitup.zerodns.co.uk.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 20}, AAAA: netParseIPMust(t, "2a02:8012:bc57:5353::10")},
	}
	snap := secondarySnapshotZone(z, records, soa)
	cfgPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("zones_dir: \""+filepath.Join(root, "zones")+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := persistSecondarySnapshot(&Config{BaseDir: root}, snap, records, soa); err != nil {
		t.Fatalf("persistSecondarySnapshot: %v", err)
	}
	loaded, err := configpkg.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load snapshot config: %v", err)
	}
	if len(loaded.Zones) != 1 {
		t.Fatalf("expected 1 snapshot zone, got %d", len(loaded.Zones))
	}
	got := loaded.Zones[0]
	if got.Lightup == nil || got.Lightup.ForwardTemplate != z.Lightup.ForwardTemplate {
		t.Fatalf("snapshot lightup = %#v", got.Lightup)
	}
	if got.Geo == nil || len(got.Geo.Named) != 1 || got.Geo.Named[0].Name != "public-v6-primary" {
		t.Fatalf("snapshot geo = %#v", got.Geo)
	}
	if got.Health == nil || got.Health.HostHeader != "lightitup.zerodns.co.uk" {
		t.Fatalf("snapshot zone health = %#v", got.Health)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].Name != "app" {
		t.Fatalf("snapshot hosts = %#v", got.Hosts)
	}
	if got.Hosts[0].Health == nil || got.Hosts[0].Health.HostHeader != "app.lightitup.zerodns.co.uk" {
		t.Fatalf("snapshot host health = %#v", got.Hosts[0].Health)
	}
	if got.Hosts[0].Geo == nil || len(got.Hosts[0].Geo.Named) != 1 || got.Hosts[0].Geo.Named[0].Name != "app-v6-primary" {
		t.Fatalf("snapshot host geo = %#v", got.Hosts[0].Geo)
	}
	if len(got.Hosts[0].Pools) != 2 {
		t.Fatalf("snapshot host pools = %#v", got.Hosts[0].Pools)
	}
}

func authSOAForTest(z Zone, serial uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:    dns.RR_Header{Name: z.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.TTLSOA},
		Ns:     "gslb.zerodns.co.uk.",
		Mbox:   z.Admin,
		Serial: serial,
		Refresh: z.Refresh,
		Retry: z.Retry,
		Expire: z.Expire,
		Minttl: z.Minttl,
	}
}

func netParseIPMust(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("parse ip %q", s)
	}
	return ip
}
