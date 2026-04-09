package config

import "testing"

func TestGenerateReverseZonesAttachesToDelegatedReverseZone(t *testing.T) {
	cfg := &Config{Zones: []Zone{
		{
			Name:      "example.org.",
			NS:        []string{"ns1.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    60,
			TTLAnswer: 20,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
			AMaster:   []IPAddr{{IP: "192.0.2.1", Reverse: true}},
		},
		{
			Name:      "2.0.192.in-addr.arpa.",
			NS:        []string{"ns1.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    60,
			TTLAnswer: 20,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
		},
	}}

	if err := GenerateReverseZones(cfg); err != nil {
		t.Fatalf("GenerateReverseZones() error = %v", err)
	}
	if len(cfg.Zones) != 2 {
		t.Fatalf("expected reverse data to attach to delegated zone, got %d zones", len(cfg.Zones))
	}
	if len(cfg.Zones[1].PTR) != 1 {
		t.Fatalf("expected 1 PTR in delegated reverse zone, got %d", len(cfg.Zones[1].PTR))
	}
	if cfg.Zones[1].PTR[0].Name != "1.2.0.192.in-addr.arpa." || cfg.Zones[1].PTR[0].PTR != "example.org." {
		t.Fatalf("unexpected PTR record %#v", cfg.Zones[1].PTR[0])
	}
}
