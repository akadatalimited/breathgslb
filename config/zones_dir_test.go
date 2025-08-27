package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadZonesDir(t *testing.T) {
	zonesDir := t.TempDir()
	zoneYAML := `- name: "example.org."
  ns: ["ns1.example.org."]
  admin: "hostmaster.example.org."
  ttl_soa: 60
  ttl_answer: 20
  refresh: 60
  retry: 30
  expire: 600
  minttl: 60
`
	if err := os.WriteFile(filepath.Join(zonesDir, "example.org.fwd.yaml"), []byte(zoneYAML), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfgYAML := "zones_dir: \"" + zonesDir + "\"\n"
	cfgFile := filepath.Join(zonesDir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("WriteFile cfg: %v", err)
	}
	c, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(c.Zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(c.Zones))
	}
	if c.Zones[0].Name != "example.org." {
		t.Fatalf("unexpected zone name %q", c.Zones[0].Name)
	}
}
