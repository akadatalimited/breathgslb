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
      forward: true
      reverse: true
      strategy: "hash"
      families:
        - family: "ipv6"
          class: "public"
          prefix: "2a02:8012:bc57::/48"
          respond_aaaa: true
          respond_ptr: true
          exclude:
            - "2a02:8012:bc57:1::/64"
        - family: "ipv6"
          class: "ula"
          prefix: "fd00:1234:5678::/48"
          respond_aaaa: true
          respond_ptr: true
        - family: "ipv4"
          class: "private"
          prefix: "172.16.0.0/24"
          respond_a: true
          respond_ptr: true
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
	if len(c.Zones[0].Lightup.Families) != 3 {
		t.Fatalf("expected 3 families, got %#v", c.Zones[0].Lightup.Families)
	}
	pub := c.Zones[0].Lightup.Families[0]
	if pub.Prefix != "2a02:8012:bc57::/48" {
		t.Fatalf("unexpected public prefix %q", pub.Prefix)
	}
	if len(pub.Exclude) != 1 || pub.Exclude[0] != "2a02:8012:bc57:1::/64" {
		t.Fatalf("unexpected public excludes %#v", pub.Exclude)
	}
	ula := c.Zones[0].Lightup.Families[1]
	if ula.Prefix != "fd00:1234:5678::/48" {
		t.Fatalf("unexpected ULA prefix %q", ula.Prefix)
	}
	priv := c.Zones[0].Lightup.Families[2]
	if priv.Prefix != "172.16.0.0/24" || !priv.RespondA || !priv.RespondPTR {
		t.Fatalf("unexpected private family %#v", priv)
	}
}
