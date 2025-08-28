package main

// zone_index.go contains helpers for building and querying an index of zone
// names and record types. The index is used when constructing DNSSEC records
// such as NSEC to describe which names and types exist in a zone.

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// zoneIndex tracks owner names and type bitmaps for NSEC.
type zoneIndex struct {
	names []string
	types map[string]map[uint16]bool
}

// buildIndex constructs a zoneIndex for quick name/type lookups.
func buildIndex(z Zone) *zoneIndex {
	m := map[string]map[uint16]bool{}
	add := func(name string, t uint16) {
		name = strings.ToLower(ensureDot(name))
		if m[name] == nil {
			m[name] = map[uint16]bool{}
		}
		m[name][t] = true
	}
	zname := ensureDot(z.Name)
	add(zname, dns.TypeSOA)
	add(zname, dns.TypeNS)

	// Possible A/AAAA at apex
	hasGeoA, hasGeoAAAA := false, false
	if z.GeoAnswers != nil {
		for _, s := range z.GeoAnswers.Country {
			if len(s.A) > 0 || len(s.APrivate) > 0 {
				hasGeoA = true
			}
			if len(s.AAAA) > 0 || len(s.AAAAPrivate) > 0 {
				hasGeoAAAA = true
			}
		}
		for _, s := range z.GeoAnswers.Continent {
			if len(s.A) > 0 || len(s.APrivate) > 0 {
				hasGeoA = true
			}
			if len(s.AAAA) > 0 || len(s.AAAAPrivate) > 0 {
				hasGeoAAAA = true
			}
		}
	}

	if len(z.AMaster)+len(z.AStandby)+len(z.AFallback) > 0 || z.Alias != "" || hasGeoA {
		add(zname, dns.TypeA)
	}
	if len(z.AAAAMaster)+len(z.AAAAStandby)+len(z.AAAAFallback) > 0 || z.Alias != "" || hasGeoAAAA {
		add(zname, dns.TypeAAAA)
	}
	for h := range z.AliasHost {
		base := strings.TrimSuffix(z.Name, ".")
		fq := h + "." + base
		add(fq, dns.TypeA)
		add(fq, dns.TypeAAAA)
	}

	for _, t := range z.TXT {
		add(ownerName(z.Name, t.Name), dns.TypeTXT)
	}
	for _, mx := range z.MX {
		add(ownerName(z.Name, mx.Name), dns.TypeMX)
	}
	for _, c := range z.CAA {
		add(ownerName(z.Name, c.Name), dns.TypeCAA)
	}
	if z.RP != nil {
		add(ownerName(z.Name, z.RP.Name), dns.TypeRP)
	}
	for _, s := range z.SSHFP {
		add(ownerName(z.Name, s.Name), dns.TypeSSHFP)
	}
	for _, s := range z.SRV {
		add(ownerName(z.Name, s.Name), dns.TypeSRV)
	}
	for _, n := range z.NAPTR {
		add(ownerName(z.Name, n.Name), dns.TypeNAPTR)
	}
	dnssecActive := z.DNSSEC != nil && z.DNSSEC.Mode != "" && z.DNSSEC.Mode != DNSSECModeOff
	if dnssecActive {
		add(zname, dns.TypeDNSKEY)
	}

	ns := make([]string, 0, len(m))
	for k := range m {
		ns = append(ns, ensureDot(strings.ToLower(k)))
	}
	if dnssecActive {
		for _, k := range ns {
			add(k, dns.TypeNSEC)
			add(k, dns.TypeRRSIG)
		}
	}
	sort.Strings(ns)
	return &zoneIndex{names: ns, types: m}
}

// hasName reports whether owner exists in the zone index.
func (z *zoneIndex) hasName(owner string) bool {
	owner = strings.ToLower(ensureDot(owner))
	_, ok := z.types[owner]
	return ok
}

// closestEncloser returns the longest existing ancestor of name.
func (z *zoneIndex) closestEncloser(name string) string {
	name = strings.ToLower(ensureDot(name))
	for {
		if z.hasName(name) {
			return name
		}
		if i := strings.Index(name, "."); i != -1 {
			name = name[i+1:]
			continue
		}
		return ""
	}
}

// nextName returns the next owner name in canonical order. If owner doesn't
// exist in the zone, the next existing name after owner is returned, wrapping
// around to the first name.
func (z *zoneIndex) nextName(owner string) string {
	owner = strings.ToLower(ensureDot(owner))
	if len(z.names) == 0 {
		return owner
	}
	i := sort.Search(len(z.names), func(j int) bool { return z.names[j] >= owner })
	if i == len(z.names) {
		return z.names[0]
	}
	if z.names[i] == owner {
		return z.names[(i+1)%len(z.names)]
	}
	return z.names[i]
}

// prevName returns the previous owner name in canonical order. If owner doesn't
// exist in the zone, the previous existing name before owner is returned,
// wrapping around to the last name.
func (z *zoneIndex) prevName(owner string) string {
	owner = strings.ToLower(ensureDot(owner))
	if len(z.names) == 0 {
		return owner
	}
	i := sort.Search(len(z.names), func(j int) bool { return z.names[j] >= owner })
	if i == len(z.names) {
		return z.names[len(z.names)-1]
	}
	if z.names[i] == owner {
		if i == 0 {
			return z.names[len(z.names)-1]
		}
		return z.names[i-1]
	}
	if i == 0 {
		return z.names[len(z.names)-1]
	}
	return z.names[i-1]
}

// typeBitmap returns the type bitmap for the given owner.
func (z *zoneIndex) typeBitmap(owner string) []uint16 {
	owner = strings.ToLower(ensureDot(owner))
	m := z.types[owner]
	if m == nil {
		return nil
	}
	var out []uint16
	for t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
