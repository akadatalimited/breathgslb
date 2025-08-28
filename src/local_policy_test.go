package main

import (
	"net"
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

// TestLocalAnswersRFCULA verifies that clients from RFC1918 and ULA networks
// receive private answers while others receive public answers.
func TestLocalAnswersRFCULA(t *testing.T) {
	cfg := &Config{EDNSBuf: 1232, Zones: []Zone{{
		Name:              "example.org.",
		NS:                []string{"ns.example.org."},
		Admin:             "hostmaster.example.org.",
		TTLSOA:            3600,
		TTLAnswer:         300,
		AMaster:           []IPAddr{{IP: "203.0.113.1"}},
		AMasterPrivate:    []IPAddr{{IP: "10.0.0.1"}},
		AAAAMaster:        []IPAddr{{IP: "2001:db8::1"}},
		AAAAMasterPrivate: []IPAddr{{IP: "fd00::1"}},
		RFCMaster:         []string{"10.0.0.0/8"},
		ULAMaster:         []string{"fd00::/8"},
	}}}
	config.SetupDefaults(cfg)

	// build authority without starting network listeners
	_, auths := buildMux(cfg, nil, nil, nil)
	auth := auths[ensureDot("example.org.")]
	auth.setMasterUp(true, true)

	tests := []struct {
		name string
		ip   net.IP
		ipv6 bool
		want string
	}{
		{"rfc", net.ParseIP("10.1.2.3"), false, "10.0.0.1"},
		{"public-v4", net.ParseIP("203.0.113.9"), false, "203.0.113.1"},
		{"ula", net.ParseIP("fd00::abcd"), true, "fd00::1"},
		{"public-v6", net.ParseIP("2001:db8::abcd"), true, "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := auth.localAnswers(tt.ipv6, tt.ip)
			if rr == nil {
				// non-local sources fall back to public answers
				rr = auth.publicFor("master", tt.ipv6)
			}
			if len(rr) != 1 {
				t.Fatalf("expected one RR, got %d", len(rr))
			}
			switch r := rr[0].(type) {
			case *dns.A:
				if tt.ipv6 {
					t.Fatalf("got A record for IPv6 test")
				}
				if r.A.String() != tt.want {
					t.Fatalf("expected %s, got %s", tt.want, r.A.String())
				}
			case *dns.AAAA:
				if !tt.ipv6 {
					t.Fatalf("got AAAA record for IPv4 test")
				}
				if r.AAAA.String() != tt.want {
					t.Fatalf("expected %s, got %s", tt.want, r.AAAA.String())
				}
			default:
				t.Fatalf("unexpected record type %T", r)
			}
		})
	}
}
