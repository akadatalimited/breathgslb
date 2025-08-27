package config

import (
	"os"
	"testing"
)

// TestLoadTXTRecords ensures that TXT records defined in YAML are parsed
// without error and retain their fields.
func TestLoadTXTRecords(t *testing.T) {
	cfgYAML := `
zones:
  - name: "example.org."
    ns: ["ns1.example.org."]
    admin: "hostmaster.example.org."
    ttl_soa: 60
    ttl_answer: 20
    refresh: 60
    retry: 30
    expire: 600
    minttl: 60
    txt:
      - text:
          - "first"
          - "second"
        ttl: 300
      - name: "_dmarc.example.org."
        text:
          - "v=DMARC1; p=none"
        ttl: 900
`

	f, err := os.CreateTemp("", "cfg-*.yaml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(cfgYAML); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(c.Zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(c.Zones))
	}
	z := c.Zones[0]

	if len(z.TXT) != 2 {
		t.Fatalf("expected 2 TXT records, got %d", len(z.TXT))
	}

	first := z.TXT[0]
	if first.TTL != 300 || len(first.Text) != 2 || first.Text[0] != "first" || first.Text[1] != "second" {
		t.Fatalf("unexpected first TXT record: %#v", first)
	}

	second := z.TXT[1]
	if second.Name != "_dmarc.example.org." || second.TTL != 900 || len(second.Text) != 1 || second.Text[0] != "v=DMARC1; p=none" {
		t.Fatalf("unexpected second TXT record: %#v", second)
	}
}
