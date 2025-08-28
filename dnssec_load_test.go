package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadDNSSECOff(t *testing.T) {
	z := Zone{Name: "example.org.", DNSSEC: &DNSSECZoneConfig{Mode: DNSSECModeOff}}
	k := loadDNSSEC(z)
	if k.enabled {
		t.Fatalf("expected DNSSEC disabled")
	}
}

func TestLoadDNSSECManual(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test: relies on Unix file permissions")
	}
	dir := t.TempDir()
	prefix := filepath.Join(dir, "key")
	keys := generateTestKeys(t, "example.org.")
	if err := writeBindKeyPair(prefix, keys.zsk, keys.zskPriv); err != nil {
		t.Fatalf("write key: %v", err)
	}
	z := Zone{Name: "example.org.", DNSSEC: &DNSSECZoneConfig{Mode: DNSSECModeManual, ZSKFile: prefix, KSKFile: prefix}}
	k := loadDNSSEC(z)
	if !k.enabled || k.zsk == nil || k.ksk == nil {
		t.Fatalf("expected keys loaded")
	}
}

func TestLoadDNSSECGenerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test: relies on Unix file permissions")
	}
	dir := t.TempDir()
	prefix := filepath.Join(dir, "gen")
	z := Zone{Name: "example.org.", DNSSEC: &DNSSECZoneConfig{Mode: DNSSECModeGenerated, ZSKFile: prefix, KSKFile: prefix}}
	k := loadDNSSEC(z)
	if !k.enabled || k.zsk == nil || k.ksk == nil {
		t.Fatalf("expected keys generated")
	}
	if _, err := os.Stat(prefix + ".key"); err != nil {
		t.Fatalf("expected pub key written: %v", err)
	}
	if _, err := os.Stat(prefix + ".private"); err != nil {
		t.Fatalf("expected priv key written: %v", err)
	}
}
