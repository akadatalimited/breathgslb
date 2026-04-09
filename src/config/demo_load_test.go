package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLightitupDemoConfig(t *testing.T) {
	srcDir := filepath.Clean(filepath.Join("..", "..", "demo", "lightitup"))
	tempDir := t.TempDir()
	zonesDir := filepath.Join(tempDir, "zones")
	reverseDir := filepath.Join(tempDir, "reverse")
	tsigDir := filepath.Join(tempDir, "tsig")
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll zones: %v", err)
	}
	if err := os.MkdirAll(reverseDir, 0o755); err != nil {
		t.Fatalf("MkdirAll reverse: %v", err)
	}
	if err := os.MkdirAll(tsigDir, 0o755); err != nil {
		t.Fatalf("MkdirAll tsig: %v", err)
	}

	zoneFiles, err := filepath.Glob(filepath.Join(srcDir, "zones", "*.fwd.yaml"))
	if err != nil {
		t.Fatalf("Glob zones: %v", err)
	}
	for _, src := range zoneFiles {
		dst := filepath.Join(zonesDir, filepath.Base(src))
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", dst, err)
		}
	}
	reverseFiles, err := filepath.Glob(filepath.Join(srcDir, "reverse", "*.rev.yaml"))
	if err != nil {
		t.Fatalf("Glob reverse: %v", err)
	}
	for _, src := range reverseFiles {
		dst := filepath.Join(reverseDir, filepath.Base(src))
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", dst, err)
		}
	}

	configSrc := filepath.Join(srcDir, "config.yaml")
	data, err := os.ReadFile(configSrc)
	if err != nil {
		t.Fatalf("ReadFile config: %v", err)
	}
	cfgText := string(data)
	cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/zones", zonesDir)
	cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/reverse", reverseDir)
	cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/tsig", tsigDir)

	cfgPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}

	c, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", cfgPath, err)
	}
	if len(c.Zones) != 2 {
		t.Fatalf("expected 2 demo zones, got %d", len(c.Zones))
	}
	var sawForward, sawReverse bool
	for _, z := range c.Zones {
		switch z.Name {
		case "lightitup.zerodns.co.uk.":
			sawForward = true
		case "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.":
			sawReverse = true
			if len(z.PTR) < 4 {
				t.Fatalf("expected populated reverse demo zone, got %#v", z.PTR)
			}
		}
	}
	if !sawForward || !sawReverse {
		t.Fatalf("expected forward and reverse demo zones, got %#v", c.Zones)
	}
}
