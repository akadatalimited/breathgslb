package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const legacyUDPLimit = 512

// RecordSizeWarnings returns advisory warnings for large-but-valid records and
// RRSets that may trigger truncation under classic UDP or the configured EDNS
// payload size. These warnings are informational and do not block startup.
func RecordSizeWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	ednsLimit := cfg.EDNSBuf
	if ednsLimit <= 0 {
		ednsLimit = 1232
	}
	var warns []string
	for _, z := range cfg.Zones {
		warns = append(warns, zoneRecordSizeWarnings(z, ednsLimit)...)
	}
	return warns
}

func zoneRecordSizeWarnings(z Zone, ednsLimit int) []string {
	var warns []string
	check := func(owner string, rrtype uint16, rrs []dns.RR, scope string) {
		if len(rrs) == 0 {
			return
		}
		m := new(dns.Msg)
		m.Answer = append(m.Answer, rrs...)
		size := m.Len()
		if size > legacyUDPLimit {
			warns = append(warns, fmt.Sprintf("%s %s/%s RRSet packs to %d bytes, exceeding classic UDP 512-byte DNS size; clients may see truncation or TCP fallback", scope, owner, dns.TypeToString[rrtype], size))
		}
		if ednsLimit > legacyUDPLimit && size > ednsLimit {
			warns = append(warns, fmt.Sprintf("%s %s/%s RRSet packs to %d bytes, exceeding configured edns_buf=%d; clients may see truncation", scope, owner, dns.TypeToString[rrtype], size, ednsLimit))
		}
	}

	apex := EnsureDot(z.Name)
	check(apex, dns.TypeA, ipRRs(apex, z.TTLAnswer, z.AMaster, false), "zone")
	check(apex, dns.TypeA, ipRRs(apex, z.TTLAnswer, z.AStandby, false), "zone")
	check(apex, dns.TypeA, ipRRs(apex, z.TTLAnswer, z.AFallback, false), "zone")
	check(apex, dns.TypeA, ipRRs(apex, z.TTLAnswer, z.AMasterPrivate, false), "zone")
	check(apex, dns.TypeA, ipRRs(apex, z.TTLAnswer, z.AStandbyPrivate, false), "zone")
	check(apex, dns.TypeA, ipRRs(apex, z.TTLAnswer, z.AFallbackPrivate, false), "zone")
	check(apex, dns.TypeAAAA, ipRRs(apex, z.TTLAnswer, z.AAAAMaster, true), "zone")
	check(apex, dns.TypeAAAA, ipRRs(apex, z.TTLAnswer, z.AAAAStandby, true), "zone")
	check(apex, dns.TypeAAAA, ipRRs(apex, z.TTLAnswer, z.AAAAFallback, true), "zone")
	check(apex, dns.TypeAAAA, ipRRs(apex, z.TTLAnswer, z.AAAAMasterPrivate, true), "zone")
	check(apex, dns.TypeAAAA, ipRRs(apex, z.TTLAnswer, z.AAAAStandbyPrivate, true), "zone")
	check(apex, dns.TypeAAAA, ipRRs(apex, z.TTLAnswer, z.AAAAFallbackPrivate, true), "zone")

	for _, h := range z.Hosts {
		owner := hostOwner(apex, h.Name)
		var v4, v6 []IPAddr
		for _, p := range h.Pools {
			if strings.EqualFold(strings.TrimSpace(p.Family), "ipv6") {
				v6 = append(v6, p.Members...)
				continue
			}
			v4 = append(v4, p.Members...)
		}
		check(owner, dns.TypeA, ipRRs(owner, z.TTLAnswer, v4, false), "host")
		check(owner, dns.TypeAAAA, ipRRs(owner, z.TTLAnswer, v6, true), "host")
	}

	for i, r := range z.TXT {
		owner := recordOwnerName(z.Name, r.Name)
		ttl := effectiveTTL(r.TTL, z.TTLAnswer)
		if len(r.Text) > 0 {
			check(owner, dns.TypeTXT, []dns.RR{&dns.TXT{Hdr: rrHdr(owner, dns.TypeTXT, ttl), Txt: r.Text}}, fmt.Sprintf("txt[%d]", i))
		}
	}
	for i, r := range z.MX {
		owner := recordOwnerName(z.Name, r.Name)
		ttl := effectiveTTL(r.TTL, z.TTLAnswer)
		check(owner, dns.TypeMX, []dns.RR{&dns.MX{Hdr: rrHdr(owner, dns.TypeMX, ttl), Preference: r.Preference, Mx: EnsureDot(r.Exchange)}}, fmt.Sprintf("mx[%d]", i))
	}
	for i, r := range z.CAA {
		owner := recordOwnerName(z.Name, r.Name)
		ttl := effectiveTTL(r.TTL, z.TTLAnswer)
		check(owner, dns.TypeCAA, []dns.RR{&dns.CAA{Hdr: rrHdr(owner, dns.TypeCAA, ttl), Flag: r.Flag, Tag: r.Tag, Value: r.Value}}, fmt.Sprintf("caa[%d]", i))
	}
	if z.RP != nil {
		owner := recordOwnerName(z.Name, z.RP.Name)
		ttl := effectiveTTL(z.RP.TTL, z.TTLAnswer)
		check(owner, dns.TypeRP, []dns.RR{&dns.RP{Hdr: rrHdr(owner, dns.TypeRP, ttl), Mbox: EnsureDot(z.RP.Mbox), Txt: EnsureDot(z.RP.Txt)}}, "rp")
	}
	for i, r := range z.SSHFP {
		owner := recordOwnerName(z.Name, r.Name)
		ttl := effectiveTTL(r.TTL, z.TTLAnswer)
		check(owner, dns.TypeSSHFP, []dns.RR{&dns.SSHFP{Hdr: rrHdr(owner, dns.TypeSSHFP, ttl), Algorithm: r.Algorithm, Type: r.Type, FingerPrint: r.Fingerprint}}, fmt.Sprintf("sshfp[%d]", i))
	}
	for i, r := range z.SRV {
		owner := recordOwnerName(z.Name, r.Name)
		ttl := effectiveTTL(r.TTL, z.TTLAnswer)
		check(owner, dns.TypeSRV, []dns.RR{&dns.SRV{Hdr: rrHdr(owner, dns.TypeSRV, ttl), Priority: r.Priority, Weight: r.Weight, Port: r.Port, Target: EnsureDot(r.Target)}}, fmt.Sprintf("srv[%d]", i))
	}
	for i, r := range z.NAPTR {
		owner := recordOwnerName(z.Name, r.Name)
		ttl := effectiveTTL(r.TTL, z.TTLAnswer)
		check(owner, dns.TypeNAPTR, []dns.RR{&dns.NAPTR{Hdr: rrHdr(owner, dns.TypeNAPTR, ttl), Order: r.Order, Preference: r.Preference, Flags: r.Flags, Service: r.Services, Regexp: r.Regexp, Replacement: EnsureDot(r.Replacement)}}, fmt.Sprintf("naptr[%d]", i))
	}
	for i, r := range z.PTR {
		owner := recordOwnerName(z.Name, r.Name)
		ttl := effectiveTTL(r.TTL, z.TTLAnswer)
		check(owner, dns.TypePTR, []dns.RR{&dns.PTR{Hdr: rrHdr(owner, dns.TypePTR, ttl), Ptr: EnsureDot(r.PTR)}}, fmt.Sprintf("ptr[%d]", i))
	}

	return warns
}

func rrHdr(name string, rrtype uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: EnsureDot(name), Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
}

func ipRRs(owner string, ttl uint32, addrs []IPAddr, ipv6 bool) []dns.RR {
	var out []dns.RR
	for _, a := range addrs {
		ip := strings.TrimSpace(a.IP)
		p := net.ParseIP(ip)
		if p == nil {
			continue
		}
		if ipv6 {
			if p.To4() != nil {
				continue
			}
			out = append(out, &dns.AAAA{Hdr: rrHdr(owner, dns.TypeAAAA, ttl), AAAA: p})
			continue
		}
		if p.To4() == nil {
			continue
		}
		out = append(out, &dns.A{Hdr: rrHdr(owner, dns.TypeA, ttl), A: p.To4()})
	}
	return out
}

func hostOwner(apex, name string) string {
	name = strings.TrimSpace(name)
	switch name {
	case "", ".", "@":
		return EnsureDot(apex)
	default:
		if strings.Contains(name, ".") {
			return EnsureDot(name)
		}
		return EnsureDot(name + "." + strings.TrimSuffix(EnsureDot(apex), "."))
	}
}
