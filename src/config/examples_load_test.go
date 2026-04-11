package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDocumentedExampleConfigs(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
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

	tests := []string{
		filepath.Join(root, "src", "doc", "examples", "config.yaml"),
		filepath.Join(root, "src", "doc", "examples", "config.sample.yaml"),
		filepath.Join(root, "src", "doc", "examples", "minimal-geo.yaml"),
	}

	for _, src := range tests {
		t.Run(filepath.Base(src), func(t *testing.T) {
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", src, err)
			}
			text := string(data)
			text = strings.ReplaceAll(text, "/etc/breathgslb/zones", zonesDir)
			text = strings.ReplaceAll(text, "/etc/breathgslb/reverse", reverseDir)
			text = strings.ReplaceAll(text, "/etc/breathgslb/tsig", tsigDir)

			cfgPath := filepath.Join(tempDir, filepath.Base(src))
			if err := os.WriteFile(cfgPath, []byte(text), 0o644); err != nil {
				t.Fatalf("WriteFile(%q): %v", cfgPath, err)
			}
			if _, err := Load(cfgPath); err != nil {
				t.Fatalf("Load(%q): %v", cfgPath, err)
			}
		})
	}
}
