package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configpkg "github.com/akadatalimited/breathgslb/src/config"
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
