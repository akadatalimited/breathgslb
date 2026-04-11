package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadForwardAndReverseModelZoneFiles(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	tempDir := t.TempDir()
	zonesDir := filepath.Join(tempDir, "zones")
	reverseDir := filepath.Join(tempDir, "reverse")
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll zones: %v", err)
	}
	if err := os.MkdirAll(reverseDir, 0o755); err != nil {
		t.Fatalf("MkdirAll reverse: %v", err)
	}

	copyModel := func(src, dst string) {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", src, err)
		}
		text := string(data)
		text = strings.ReplaceAll(text, "/etc/breathgslb/zones", zonesDir)
		text = strings.ReplaceAll(text, "/etc/breathgslb/reverse", reverseDir)
		if err := os.WriteFile(dst, []byte(text), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", dst, err)
		}
	}

	copyModel(filepath.Join(root, "model", "forward.model.yml"), filepath.Join(zonesDir, "forward.fwd.yaml"))
	copyModel(filepath.Join(root, "model", "reverse.model.yml"), filepath.Join(reverseDir, "reverse.rev.yaml"))

	cfgText := "zones_dir: \"" + zonesDir + "\"\nreverse_dir: \"" + reverseDir + "\"\n"
	cfgPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", cfgPath, err)
	}
	if len(cfg.Zones) < 2 {
		t.Fatalf("expected at least 2 model zones, got %d", len(cfg.Zones))
	}
	var sawForward, sawReverse bool
	for _, z := range cfg.Zones {
		if z.Name == "example.net." {
			sawForward = true
		}
		if z.Name == "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa." {
			sawReverse = true
		}
	}
	if !sawForward || !sawReverse {
		t.Fatalf("expected forward and reverse model zones, got %#v", cfg.Zones)
	}
}

func TestParseMainConfigModelFiles(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	paths := []string{
		filepath.Join(root, "model", "config.primary.model.yaml"),
		filepath.Join(root, "model", "config.secondary.model.yml"),
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", path, err)
			}
			var cfg Config
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("yaml.Unmarshal(%q): %v", path, err)
			}
		})
	}
}
