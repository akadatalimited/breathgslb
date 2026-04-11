package main

import (
	"testing"
	"time"
)

// Test that serial values persist across restarts and advance with time.
func TestSerialPersistenceRestart(t *testing.T) {
	tmp := t.TempDir()
	oldDir := serialDir
	serialDir = tmp
	t.Cleanup(func() { serialDir = oldDir })

	oldNow := serialNow
	defer func() { serialNow = oldNow }()

	cfg := &Config{CooldownSec: 1, Zones: []Zone{{Name: "example.com."}}}

	serialNow = func() time.Time { return time.Date(2026, time.April, 11, 5, 52, 10, 0, time.UTC) }
	_, auths := buildMux(cfg, nil, nil, nil)
	a := auths[ensureDot("example.com")]
	if a.serial != 2026041100 {
		t.Fatalf("expected serial 2026041100, got %d", a.serial)
	}
	a.cancel()

	serialNow = func() time.Time { return time.Date(2026, time.April, 11, 5, 53, 10, 0, time.UTC) }
	_, auths = buildMux(cfg, nil, nil, nil)
	a = auths[ensureDot("example.com")]
	if a.serial != 2026041101 {
		t.Fatalf("expected serial 2026041101 after restart, got %d", a.serial)
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

	serialNow = func() time.Time { return time.Date(2026, time.April, 11, 5, 52, 10, 0, time.UTC) }
	_, auths := buildMux(cfg, nil, nil, nil)
	a := auths[ensureDot("example.com")]
	if a.serial != 2026041100 {
		t.Fatalf("expected serial 2026041100, got %d", a.serial)
	}
	a.cancel()

	serialNow = func() time.Time { return time.Date(2026, time.April, 10, 5, 52, 10, 0, time.UTC) }
	_, auths = buildMux(cfg, nil, nil, nil)
	a = auths[ensureDot("example.com")]
	if a.serial != 2026041101 {
		t.Fatalf("expected serial 2026041101 after rollback, got %d", a.serial)
	}
	a.cancel()
}
