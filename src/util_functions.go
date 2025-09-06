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
	// synthetic apex records
	add(ensureDot(z.Name), dns.TypeSOA)
	add(ensureDot(z.Name), dns.TypeNS)
	if len(z.AMaster) > 0 || len(z.AStandby) > 0 || len(z.AFallback) > 0 {
		add(ensureDot(z.Name), dns.TypeA)
	}
	if len(z.AAAAMaster) > 0 || len(z.AAAAStandby) > 0 || len(z.AAAAFallback) > 0 {
		add(ensureDot(z.Name), dns.TypeAAAA)
	}
	// static records
	for _, t := range z.TXT {
		name := ownerName(z.Name, t.Name)
		add(name, dns.TypeTXT)
	}
	for _, mx := range z.MX {
		name := ownerName(z.Name, mx.Name)
		add(name, dns.TypeMX)
	}
	for _, c := range z.CAA {
		name := ownerName(z.Name, c.Name)
		add(name, dns.TypeCAA)
	}
	if z.RP != nil {
		name := ownerName(z.Name, z.RP.Name)
		add(name, dns.TypeRP)
	}
	for _, s := range z.SSHFP {
		name := ownerName(z.Name, s.Name)
		add(name, dns.TypeSSHFP)
	}
	for _, s := range z.SRV {
		name := ownerName(z.Name, s.Name)
		add(name, dns.TypeSRV)
	}
	for _, n := range z.NAPTR {
		name := ownerName(z.Name, n.Name)
		add(name, dns.TypeNAPTR)
	}
	// collect and sort names
	var names []string
	for name := range m {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return canonicalLess(names[i], names[j]) })
	return &zoneIndex{names: names, types: m}
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
	for _, rr := range rrs {
		h := rr.Header()
		name := strings.ToLower(ensureDot(h.Name))
		add(name, h.Rrtype)
	}
	// collect and sort names
	var names []string
	for name := range m {
		names = append(names, name)
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
	i := sort.Search(len(z.names), func(i int) bool { return !canonicalLess(z.names[i], name) })
	if i == 0 {
		return ""
	}
	return z.names[i-1]
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
