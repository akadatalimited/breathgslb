package main

import "testing"

// Test that serial values persist across restarts and advance with time.
func TestSerialPersistenceRestart(t *testing.T) {
	tmp := t.TempDir()
	oldDir := serialDir
	serialDir = tmp
	t.Cleanup(func() { serialDir = oldDir })

	oldNow := serialNow
	defer func() { serialNow = oldNow }()

	cfg := &Config{CooldownSec: 1, Zones: []Zone{{Name: "example.com."}}}

	serialNow = func() uint32 { return 100 }
	_, auths := buildMux(cfg, nil, nil)
	a := auths[ensureDot("example.com")]
	if a.serial != 100 {
		t.Fatalf("expected serial 100, got %d", a.serial)
	}
	a.cancel()

	serialNow = func() uint32 { return 200 }
	_, auths = buildMux(cfg, nil, nil)
	a = auths[ensureDot("example.com")]
	if a.serial != 200 {
		t.Fatalf("expected serial 200 after restart, got %d", a.serial)
	}
	a.cancel()
}

// Test that serial increases if the clock moves backwards.
func TestSerialClockRollback(t *testing.T) {
	tmp := t.TempDir()
	oldDir := serialDir
	serialDir = tmp
	t.Cleanup(func() { serialDir = oldDir })

	oldNow := serialNow
	defer func() { serialNow = oldNow }()

	cfg := &Config{CooldownSec: 1, Zones: []Zone{{Name: "example.com."}}}

	serialNow = func() uint32 { return 100 }
	_, auths := buildMux(cfg, nil, nil)
	a := auths[ensureDot("example.com")]
	if a.serial != 100 {
		t.Fatalf("expected serial 100, got %d", a.serial)
	}
	a.cancel()

	serialNow = func() uint32 { return 50 }
	_, auths = buildMux(cfg, nil, nil)
	a = auths[ensureDot("example.com")]
	if a.serial != 101 {
		t.Fatalf("expected serial 101 after rollback, got %d", a.serial)
	}
	a.cancel()
}
