package main

import (
	"sort"
	"strings"

	config "github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

// Utility functions

// buildIndex constructs a zoneIndex for quick name/type lookups.
func buildIndex(z config.Zone) *zoneIndex {
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
		fqdn := ensureDot(h)
		if !strings.HasSuffix(strings.ToLower(fqdn), strings.ToLower(zname)) {
			fqdn = ensureDot(strings.TrimSuffix(h, ".") + "." + strings.TrimSuffix(z.Name, "."))
		}
		add(fqdn, dns.TypeA)
		add(fqdn, dns.TypeAAAA)
	}

	// static records
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
	for _, p := range z.PTR {
		add(ownerName(z.Name, p.Name), dns.TypePTR)
	}

	dnssecActive := z.DNSSEC != nil && z.DNSSEC.Mode != "" && z.DNSSEC.Mode != DNSSECModeOff
	if dnssecActive {
		add(zname, dns.TypeDNSKEY)
	}

	var names []string
	for name := range m {
		names = append(names, ensureDot(strings.ToLower(name)))
	}
	if dnssecActive {
		for _, name := range names {
			add(name, dns.TypeRRSIG)
			if z.DNSSEC.NSEC3Iterations > 0 {
				add(name, dns.TypeNSEC3)
			} else {
				add(name, dns.TypeNSEC)
			}
		}
	}
	sort.Slice(names, func(i, j int) bool { return canonicalLess(names[i], names[j]) })

	idx := &zoneIndex{names: names, types: m}
	if dnssecActive && z.DNSSEC.NSEC3Iterations > 0 {
		idx.nsec3Owner = make(map[string]string, len(names))
		for _, name := range names {
			hash := strings.ToLower(dns.HashName(name, dns.SHA1, z.DNSSEC.NSEC3Iterations, z.DNSSEC.NSEC3Salt))
			idx.nsec3Names = append(idx.nsec3Names, hash)
			idx.nsec3Owner[hash] = name
		}
		sort.Strings(idx.nsec3Names)
	}
	return idx
}

// buildIndexFromRRs constructs a zoneIndex from a list of RRs.
func buildIndexFromRRs(apex string, rrs []dns.RR) *zoneIndex {
	m := map[string]map[uint16]bool{}
	add := func(name string, t uint16) {
		name = strings.ToLower(ensureDot(name))
		if m[name] == nil {
			m[name] = map[uint16]bool{}
		}
		m[name][t] = true
	}
	add(ensureDot(apex), dns.TypeSOA)
	for _, rr := range rrs {
		h := rr.Header()
		name := strings.ToLower(ensureDot(h.Name))
		add(name, h.Rrtype)
	}
	var names []string
	for name := range m {
		names = append(names, ensureDot(strings.ToLower(name)))
	}
	sort.Slice(names, func(i, j int) bool { return canonicalLess(names[i], names[j]) })
	return &zoneIndex{names: names, types: m}
}

// hasName reports whether the index contains a given owner name.
func (z *zoneIndex) hasName(name string) bool {
	if z == nil {
		return false
	}
	name = strings.ToLower(ensureDot(name))
	_, ok := z.types[name]
	return ok
}

// prevName returns the predecessor of name in canonical order.
func (z *zoneIndex) prevName(name string) string {
	if z == nil {
		return ""
	}
	name = strings.ToLower(ensureDot(name))
	if len(z.names) == 0 {
		return name
	}
	return z.names[predecessor(z.names, name)]
}

// closestEncloser returns the longest existing encloser of name.
func (z *zoneIndex) closestEncloser(name string) string {
	if z == nil {
		return ""
	}
	name = strings.ToLower(ensureDot(name))
	for {
		if z.hasName(name) {
			return name
		}
		if i := strings.Index(name, "."); i >= 0 {
			name = name[i+1:]
		} else {
			return ""
		}
	}
}

// rrDiff computes the difference between two RR sets.
func rrDiff(old, new []dns.RR) (del, add []dns.RR) {
	o := map[string]dns.RR{}
	for _, r := range old {
		o[r.String()] = r
	}
	n := map[string]dns.RR{}
	for _, r := range new {
		n[r.String()] = r
	}
	for k, r := range o {
		if _, ok := n[k]; !ok {
			del = append(del, r)
		}
	}
	for k, r := range n {
		if _, ok := o[k]; !ok {
			add = append(add, r)
		}
	}
	sort.Slice(del, func(i, j int) bool { return del[i].String() < del[j].String() })
	sort.Slice(add, func(i, j int) bool { return add[i].String() < add[j].String() })
	return
}
