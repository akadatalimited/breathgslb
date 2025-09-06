package main

import (
	"log"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// makeNSEC3 builds an NSEC3 record for the provided owner name.
func (a *authority) makeNSEC3(owner string) dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	if a.zidx == nil || !a.zidx.hasName(owner) {
		return nil
	}
	
	// Check if NSEC3 is enabled
	if a.keys == nil || !a.keys.enabled || a.keys.nsec3Iterations == 0 {
		return nil
	}
	
	// Hash the owner name
	ownerHash, err := dns.HashName(owner, dns.SHA1, a.keys.nsec3Iterations, a.keys.nsec3Salt)
	if err != nil {
		log.Printf("nsec3 hash failed for %s: %v", owner, err)
		return nil
	}
	
	// Find the next hashed name in the zone
	nextOwner := a.zidx.nextName(owner)
	nextHash, err := dns.HashName(nextOwner, dns.SHA1, a.keys.nsec3Iterations, a.keys.nsec3Salt)
	if err != nil {
		log.Printf("nsec3 hash failed for next name %s: %v", nextOwner, err)
		return nil
	}
	
	// Get the types for this owner
	typesHere := a.zidx.typeBitmap(owner)
	zname := strings.ToLower(ensureDot(a.zone.Name))
	
	// Filter out apex-only types for non-apex names
	bm := make([]uint16, 0, len(typesHere)+2)
	if owner == zname {
		bm = append(bm, typesHere...)
	} else {
		for _, t := range typesHere {
			if t == dns.TypeSOA || t == dns.TypeDNSKEY {
				continue
			}
			bm = append(bm, t)
		}
	}
	
	// Always include NSEC3 and RRSIG in the bitmap
	hasNSEC3, hasRRSIG := false, false
	for _, t := range bm {
		if t == dns.TypeNSEC3 {
			hasNSEC3 = true
		}
		if t == dns.TypeRRSIG {
			hasRRSIG = true
		}
	}
	if !hasNSEC3 {
		bm = append(bm, dns.TypeNSEC3)
	}
	if !hasRRSIG {
		bm = append(bm, dns.TypeRRSIG)
	}
	sort.Slice(bm, func(i, j int) bool { return bm[i] < bm[j] })
	
	// Create the NSEC3 record
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ensureDot(a.zone.Name), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: a.zone.TTLAnswer},
		Hash:       dns.SHA1,
		Flags:      0, // Set to 1 for opt-out if needed
		Iterations: a.keys.nsec3Iterations,
		Salt:       a.keys.nsec3Salt,
		NextDomain: nextHash,
		TypeBitMap: bm,
	}
}

// makeNSEC3PARAM builds an NSEC3PARAM record for the zone.
func (a *authority) makeNSEC3PARAM() dns.RR {
	if a.keys == nil || !a.keys.enabled || a.keys.nsec3Iterations == 0 {
		return nil
	}
	
	return &dns.NSEC3PARAM{
		Hdr:        dns.RR_Header{Name: ensureDot(a.zone.Name), Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: a.zone.TTLAnswer},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: a.keys.nsec3Iterations,
		Salt:       a.keys.nsec3Salt,
	}
}