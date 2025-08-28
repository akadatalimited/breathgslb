package main

import (
	"testing"

	"github.com/miekg/dns"
)

func containsType(ts []uint16, t uint16) bool {
	for _, v := range ts {
		if v == t {
			return true
		}
	}
	return false
}

func TestMakeNSECTypeFiltering(t *testing.T) {
	z := Zone{
		Name:    "example.com",
		NS:      []string{"ns1.example.net."},
		AMaster: []IPAddr{{IP: "1.1.1.1"}},
		TXT:     []TXTRecord{{Name: "foo.example.com", Text: []string{"bar"}}},
		DNSSEC:  &DNSSECZoneConfig{Mode: DNSSECModeManual},
	}
	idx := buildIndex(z)
	a := &authority{zone: z, zidx: idx}

	apex := a.makeNSEC("example.com")
	if apex == nil {
		t.Fatalf("expected NSEC for apex")
	}
	abm := apex.(*dns.NSEC).TypeBitMap
	for _, tt := range []uint16{dns.TypeSOA, dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeRRSIG} {
		if !containsType(abm, tt) {
			t.Fatalf("apex bitmap missing type %d", tt)
		}
	}

	foo := a.makeNSEC("foo.example.com")
	if foo == nil {
		t.Fatalf("expected NSEC for foo.example.com")
	}
	fbm := foo.(*dns.NSEC).TypeBitMap
	if containsType(fbm, dns.TypeSOA) || containsType(fbm, dns.TypeDNSKEY) {
		t.Fatalf("foo.example.com bitmap should not contain SOA or DNSKEY: %v", fbm)
	}
	for _, tt := range []uint16{dns.TypeNSEC, dns.TypeRRSIG} {
		if !containsType(fbm, tt) {
			t.Fatalf("foo.example.com bitmap missing type %d", tt)
		}
	}
}
