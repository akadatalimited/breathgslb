package main

import (
	"testing"

	"github.com/miekg/dns"
)

// helper function to check presence in bitmap
func hasType(ts []uint16, t uint16) bool {
	for _, v := range ts {
		if v == t {
			return true
		}
	}
	return false
}

func TestBuildIndexAndQueries(t *testing.T) {
	z := Zone{
		Name:       "example.com",
		AMaster:    []IPAddr{{IP: "1.1.1.1"}},
		AAAAMaster: []IPAddr{{IP: "2001:db8::1"}},
		TXT:        []TXTRecord{{Text: []string{"txt"}}},
		MX:         []MXRecord{{Preference: 10, Exchange: "mail.example.com."}},
		CAA:        []CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}},
		RP:         &RPRecord{Mbox: "hostmaster.example.com.", Txt: "info.example.com."},
		SSHFP:      []SSHFPRecord{{Algorithm: 1, Type: 1, Fingerprint: "abcd"}},
		SRV:        []SRVRecord{{Name: "_sip._tcp.example.com", Priority: 10, Weight: 5, Port: 5060, Target: "sip.example.com."}},
		NAPTR:      []NAPTRRecord{{Order: 1, Preference: 1, Flags: "u", Services: "SIP+D2T", Regexp: "!^.*$!sip:service@example.com!", Replacement: "."}},
		DNSSEC:     &DNSSECZoneConfig{Enable: true},
	}

	idx := buildIndex(z)

	if !idx.hasName("example.com") {
		t.Fatalf("expected apex name present")
	}
	if !idx.hasName("_sip._tcp.example.com") {
		t.Fatalf("expected SRV owner present")
	}
	if idx.hasName("missing.example.com") {
		t.Fatalf("did not expect unknown name")
	}

	next := idx.nextName("_sip._tcp.example.com")
	if next != "example.com." {
		t.Fatalf("expected next name example.com. got %s", next)
	}
	wrap := idx.nextName("example.com")
	if wrap != "_sip._tcp.example.com." {
		t.Fatalf("expected wrap to first name, got %s", wrap)
	}

	apexTypes := idx.typeBitmap("example.com")
	for _, tt := range []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeMX, dns.TypeCAA, dns.TypeRP, dns.TypeSSHFP, dns.TypeNAPTR, dns.TypeDNSKEY, dns.TypeRRSIG} {
		if !hasType(apexTypes, tt) {
			t.Fatalf("expected type %d in apex bitmap", tt)
		}
	}
	if hasType(apexTypes, dns.TypeSRV) {
		t.Fatalf("did not expect SRV at apex")
	}

	srvTypes := idx.typeBitmap("_sip._tcp.example.com")
	if !hasType(srvTypes, dns.TypeSRV) {
		t.Fatalf("expected SRV type for _sip._tcp.example.com")
	}
}
