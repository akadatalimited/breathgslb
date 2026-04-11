package config

import (
	"strings"
	"testing"
)

func TestRecordSizeWarningsForLargeAAAAHostRRSet(t *testing.T) {
	cfg := &Config{
		EDNSBuf: 1232,
		Zones: []Zone{{
			Name:      "example.org.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    300,
			TTLAnswer: 60,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
			Hosts: []Host{{
				Name: "app",
				Pools: []Pool{{
					Name:   "app-v6",
					Family: "ipv6",
					Members: []IPAddr{
						{IP: "2001:db8::1"}, {IP: "2001:db8::2"}, {IP: "2001:db8::3"}, {IP: "2001:db8::4"},
						{IP: "2001:db8::5"}, {IP: "2001:db8::6"}, {IP: "2001:db8::7"}, {IP: "2001:db8::8"},
						{IP: "2001:db8::9"}, {IP: "2001:db8::a"}, {IP: "2001:db8::b"}, {IP: "2001:db8::c"},
						{IP: "2001:db8::d"}, {IP: "2001:db8::e"}, {IP: "2001:db8::f"}, {IP: "2001:db8::10"},
						{IP: "2001:db8::11"}, {IP: "2001:db8::12"}, {IP: "2001:db8::13"}, {IP: "2001:db8::14"},
					},
				}},
			}},
		}},
	}

	warns := RecordSizeWarnings(cfg)
	if len(warns) == 0 {
		t.Fatalf("expected at least one size warning, got none")
	}
	var sawHostAAAA bool
	for _, w := range warns {
		if strings.Contains(w, "app.example.org.") && strings.Contains(w, "AAAA") {
			sawHostAAAA = true
			break
		}
	}
	if !sawHostAAAA {
		t.Fatalf("expected host AAAA warning, got %v", warns)
	}
}

func TestRecordSizeWarningsQuietForSmallRecords(t *testing.T) {
	cfg := &Config{
		EDNSBuf: 1232,
		Zones: []Zone{{
			Name:      "example.org.",
			NS:        []string{"ns.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    300,
			TTLAnswer: 60,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
			TXT:       []TXTRecord{{Name: "example.org.", Text: []string{"ok"}}},
		}},
	}

	if warns := RecordSizeWarnings(cfg); len(warns) != 0 {
		t.Fatalf("expected no warnings, got %v", warns)
	}
}
