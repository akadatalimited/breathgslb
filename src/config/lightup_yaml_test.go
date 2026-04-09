package config

import (
	"os"
	"testing"
)

func TestLoadLightupConfig(t *testing.T) {
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
    lightup:
      enabled: true
      reverse: true
      strategy: "hash"
      families:
        - family: "ipv6"
          class: "public"
          prefix: "2a02:8012:bc57::/48"
          respond_ptr: true
          exclude:
            - "2a02:8012:bc57:1::/64"
`

	f, err := os.CreateTemp("", "cfg-lightup-*.yaml")
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
	if c.Zones[0].Lightup == nil {
		t.Fatalf("expected lightup config to be loaded")
	}
	if len(c.Zones[0].Lightup.Families) != 1 {
		t.Fatalf("expected 1 family, got %#v", c.Zones[0].Lightup.Families)
	}
	fam := c.Zones[0].Lightup.Families[0]
	if fam.Prefix != "2a02:8012:bc57::/48" {
		t.Fatalf("unexpected prefix %q", fam.Prefix)
	}
	if len(fam.Exclude) != 1 || fam.Exclude[0] != "2a02:8012:bc57:1::/64" {
		t.Fatalf("unexpected excludes %#v", fam.Exclude)
	}
}
