package config

import (
	"os"
	"testing"
)

func TestLoadPoolsAndNamedGeoPolicy(t *testing.T) {
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
    pools:
      - name: "eu-v6"
        family: "ipv6"
        class: "public"
        role: "primary"
        members:
          - ip: "2001:db8::1"
      - name: "us-v4"
        family: "ipv4"
        class: "public"
        role: "secondary"
        members:
          - ip: "198.51.100.1"
    geo:
      eu-v6:
        allow_continents: ["EU"]
      us-v4:
        allow_countries: ["US"]
      fallback:
        allow_all: true
`

	f, err := os.CreateTemp("", "cfg-pools-*.yaml")
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
	z := c.Zones[0]
	if len(z.Pools) != 2 {
		t.Fatalf("expected 2 pools, got %#v", z.Pools)
	}
	if z.Geo == nil || len(z.Geo.Named) != 2 {
		t.Fatalf("expected named geo policies, got %#v", z.Geo)
	}
	if z.Geo.Named[0].Name != "eu-v6" || len(z.Geo.Named[0].Policy.AllowContinents) != 1 {
		t.Fatalf("unexpected first named geo policy %#v", z.Geo.Named[0])
	}
	if !z.Geo.Fallback.AllowAll {
		t.Fatalf("expected fallback allow_all, got %#v", z.Geo.Fallback)
	}
}
