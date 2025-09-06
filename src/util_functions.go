package main

import (
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Utility functions

// canonicalLess compares two domain names using the DNSSEC canonical
// ordering as defined in RFC4034 §6.1. Labels are compared
// case-insensitively from right to left. The shorter name sorts first
// when all compared labels are equal.
func canonicalLess(a, b string) bool {
	a = strings.ToLower(ensureDot(a))
	b = strings.ToLower(ensureDot(b))
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i, j := len(as)-1, len(bs)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if as[i] == bs[j] {
			continue
		}
		return as[i] < bs[j]
	}
	return len(as) < len(bs)
}

// zoneIndex tracks owner names and type bitmaps for NSEC.
type zoneIndex struct {
	names []string
	types map[string]map[uint16]bool
}

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
	// synthetic apex records
	add(zname, dns.TypeSOA)
	add(zname, dns.TypeNS)
	if len(z.AMaster) > 0 || len(z.AStandby) > 0 || len(z.AFallback) > 0 {
		add(zname, dns.TypeA)
	}
	if len(z.AAAAMaster) > 0 || len(z.AAAAStandby) > 0 || len(z.AAAAFallback) > 0 {
		add(zname, dns.TypeAAAA)
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
	zname := ensureDot(apex)
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

// clientIP extracts the client IP from a DNS request.
func clientIP(w dns.ResponseWriter, r *dns.Msg) net.IP {
	// Prefer ECS if present
	if opt := r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*dns.EDNS0_SUBNET); ok {
				if s.Address != nil {
					return s.Address
				}
			}
		}
	}
	addr := w.RemoteAddr()
	ua, _ := net.ResolveUDPAddr("udp", addr.String())
	if ua != nil && ua.IP != nil {
		return ua.IP
	}
	ta, _ := net.ResolveTCPAddr("tcp", addr.String())
	if ta != nil {
		return ta.IP
	}
	return nil
}

// pickAddr selects an address from a list based on the persistence mode.
func pickAddr(addrs []string, mode string, ctr *atomic.Uint64) string {
	if len(addrs) == 0 {
		return ""
	}
	switch strings.ToLower(mode) {
	case "random":
		return addrs[rand.Intn(len(addrs))]
	case "wrr", "rr":
		fallthrough
	default:
		idx := ctr.Add(1) - 1
		return addrs[int(idx)%len(addrs)]
	}
}

// inAnyCIDR checks if an IP is contained in any of the provided CIDR blocks.
func inAnyCIDR(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ensureDot ensures a domain name ends with a dot.
func ensureDot(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

// ownerName constructs an owner name from an apex and relative name.
func ownerName(apex, s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == "@" {
		return ensureDot(apex)
	}
	return ensureDot(s)
}

// hdr creates a DNS RR header.
func hdr(name string, t uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
}

// wantDNSSEC checks if a DNS query requests DNSSEC records.
func wantDNSSEC(r *dns.Msg) bool {
	if o := r.IsEdns0(); o != nil {
		return o.Do()
	}
	return false
}