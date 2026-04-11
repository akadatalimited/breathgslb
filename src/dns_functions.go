package main

import (
	"context"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

// DNS-related functions

func (a *authority) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if o := r.IsEdns0(); o != nil {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(o.UDPSize())
		if o.Do() {
			opt.SetDo()
		}
		for _, e := range o.Option {
			if c, ok := e.(*dns.EDNS0_COOKIE); ok {
				cc := *c
				opt.Option = append(opt.Option, &cc)
			}
		}
		m.Extra = append(m.Extra, opt)
	}
	m.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(ensureDot(q.Name))
	zone := ensureDot(a.zone.Name)
	z := strings.ToLower(zone)

	if a.cfg.LogQueries {
		log.Printf("query %s %s", name, dns.TypeToString[q.Qtype])
	}

	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		if name != z {
			m.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		if !a.xfrAllowed(w, r) {
			m.SetRcode(r, dns.RcodeRefused)
			if ts := r.IsTsig(); ts != nil {
				m.SetTsig(ts.Hdr.Name, ts.Algorithm, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
			return
		}
		a.xfr(w, r, q.Qtype == dns.TypeIXFR)
		return
	}

	if strings.ToLower(a.zone.Serve) == "secondary" {
		cIP := clientIP(w, r)
		a.mu.RLock()
		if q.Qtype == dns.TypeSOA && name == z {
			if a.soaRR != nil {
				rr := *a.soaRR
				m.Answer = append(m.Answer, &rr)
			}
		} else {
			for _, rr := range a.records[name] {
				if rr.Header().Rrtype == dns.TypeRRSIG {
					continue
				}
				if q.Qtype == dns.TypeANY || rr.Header().Rrtype == q.Qtype {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if len(m.Answer) == 0 && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, a.lightupARecords(name, cIP)...)
		}
		if len(m.Answer) == 0 && q.Qtype == dns.TypeAAAA {
			m.Answer = append(m.Answer, a.lightupAAAARecords(name, cIP)...)
		}
		if len(m.Answer) == 0 && q.Qtype == dns.TypePTR {
			if rr := a.lightupPTRRecord(name); rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		if len(m.Answer) == 0 {
			missing := a.zidx == nil || !a.zidx.hasName(name)
			if missing {
				m.SetRcode(r, dns.RcodeNameError)
			}
			for _, rr := range a.records[z] {
				if rr.Header().Rrtype == dns.TypeNS {
					m.Ns = append(m.Ns, rr)
				}
			}
			if a.soaRR != nil {
				rr := *a.soaRR
				m.Ns = append(m.Ns, &rr)
			}
			if wantDNSSEC(r) && a.secondaryDNSSECAvailable() {
				m.Ns = append(m.Ns, a.secondaryDenialProofs(name, missing, cIP, r)...)
			}
		} else if wantDNSSEC(r) && q.Qtype != dns.TypeANY {
			sigs := a.secondaryRRSIGs(name, q.Qtype)
			if len(sigs) > 0 {
				m.Answer = append(m.Answer, sigs...)
			} else if a.keys != nil && a.keys.enabled {
				m.Answer = a.signAll(m.Answer)
			}
		}
		a.mu.RUnlock()
		_ = w.WriteMsg(m)
		return
	}

	if name == z && q.Qtype == dns.TypeSOA {
		m.Answer = append(m.Answer, a.soa())
		if wantDNSSEC(r) && a.keys != nil && a.keys.enabled {
			m.Answer = a.signAll(m.Answer)
		}
		_ = w.WriteMsg(m)
		return
	}

	// Basic apex handling for SOA/NS/DNSKEY/NSEC3PARAM
	if name == z {
		switch q.Qtype {
		case dns.TypeNS:
			for _, ns := range a.zone.NS {
				m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(zone, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
			}
		case dns.TypeDNSKEY:
			if a.keys != nil && a.keys.enabled {
				for _, k := range a.dnskeyRRSet() {
					m.Answer = append(m.Answer, k)
				}
				if wantDNSSEC(r) {
					m.Answer = a.signAll(m.Answer)
				}
			}
		case dns.TypeNSEC3PARAM:
			// Return NSEC3PARAM record when NSEC3 is enabled
			if a.keys != nil && a.keys.enabled && a.keys.nsec3Iterations > 0 {
				if nsec3param := a.makeNSEC3PARAM(); nsec3param != nil {
					m.Answer = append(m.Answer, nsec3param)
					if wantDNSSEC(r) {
						// Only sign the NSEC3PARAM record, not other records
						if sig := a.makeRRSIG([]dns.RR{nsec3param}, a.keys.zsk); sig != nil {
							if err := sig.Sign(a.keys.zskPriv, []dns.RR{nsec3param}); err == nil {
								m.Answer = append(m.Answer, sig)
							} else {
								log.Printf("dnssec sign error for NSEC3PARAM: %v", err)
							}
						}
					}
				}
			}
		}
	}

	// client identity (ECS or source)
	cIP := clientIP(w, r)

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, a.addrA(name, cIP, r)...)
	case dns.TypeAAAA:
		m.Answer = append(m.Answer, a.addrAAAA(name, cIP, r)...)
	case dns.TypeTXT:
		m.Answer = append(m.Answer, a.txtFor(name)...)
	case dns.TypeMX:
		m.Answer = append(m.Answer, a.mxFor(name)...)
	case dns.TypeCAA:
		m.Answer = append(m.Answer, a.caaFor(name)...)
	case dns.TypeRP:
		if rr := a.rpFor(name); rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeSSHFP:
		m.Answer = append(m.Answer, a.sshfpFor(name)...)
	case dns.TypeSRV:
		m.Answer = append(m.Answer, a.srvFor(name)...)
	case dns.TypeNAPTR:
		m.Answer = append(m.Answer, a.naptrFor(name)...)
	case dns.TypePTR:
		m.Answer = append(m.Answer, a.ptrFor(name)...)
	case dns.TypeNSEC3PARAM:
		// NSEC3PARAM is handled in the apex section above
	}

	if len(m.Answer) == 0 {
		for _, ns := range a.zone.NS {
			m.Ns = append(m.Ns, &dns.NS{Hdr: hdr(zone, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
		}
		m.Ns = append(m.Ns, a.soa())
		missing := !a.authoritativeNameExists(name)
		if missing {
			m.SetRcode(r, dns.RcodeNameError)
		}
		if wantDNSSEC(r) && a.keys != nil && a.keys.enabled && a.zidx != nil {
			if missing {
				if a.keys.nsec3Iterations > 0 {
					m.Ns = append(m.Ns, a.nsec3DenialProofs(name)...)
				} else {
					closest := a.zidx.closestEncloser(name)
					nsecMap := map[string]*dns.NSEC{}
					var order []string
					if n := a.makeNSEC(a.zidx.prevName(name)); n != nil {
						ns := n.(*dns.NSEC)
						key := strings.ToLower(ns.Hdr.Name) + "|" + strings.ToLower(ns.NextDomain)
						if _, ok := nsecMap[key]; !ok {
							nsecMap[key] = ns
							order = append(order, key)
						}
					}
					if closest != "" {
						if n := a.makeNSEC(a.zidx.prevName("*." + closest)); n != nil {
							ns := n.(*dns.NSEC)
							key := strings.ToLower(ns.Hdr.Name) + "|" + strings.ToLower(ns.NextDomain)
							if _, ok := nsecMap[key]; !ok {
								nsecMap[key] = ns
								order = append(order, key)
							}
						}
					}
					for _, k := range order {
						m.Ns = append(m.Ns, nsecMap[k])
					}
				}
			} else {
				if a.keys.nsec3Iterations > 0 {
					if nsec3 := a.makeNSEC3ForQuery(name, cIP, r); nsec3 != nil {
						m.Ns = append(m.Ns, nsec3)
					}
				} else {
					if nsec := a.makeNSECForQuery(name, cIP, r); nsec != nil {
						m.Ns = append(m.Ns, nsec)
					}
				}
			}
		}
	}

	if wantDNSSEC(r) && a.keys != nil && a.keys.enabled {
		m.Answer = a.signAll(m.Answer)
		m.Ns = a.signAll(m.Ns)
	}
	_ = w.WriteMsg(m)
}

func (a *authority) xfrAllowed(w dns.ResponseWriter, r *dns.Msg) bool {
	configs := transferTSIGConfigs(a.cfg, a.zone.TSIG)
	if len(configs) == 0 {
		return true
	}
	ts := r.IsTsig()
	if ts == nil || w.TsigStatus() != nil {
		for _, cfg := range configs {
			if cfg.AllowUnsigned {
				return true
			}
		}
		return false
	}
	ip := clientIP(w, r)
	keyName := ensureDot(ts.Hdr.Name)
	for _, cfg := range configs {
		for _, k := range cfg.Keys {
			if ensureDot(k.Name) != keyName {
				continue
			}
			if len(k.AllowXFRFrom) == 0 {
				return true
			}
			for _, allow := range k.AllowXFRFrom {
				if allowXFRFromMatches(ip, allow) {
					return true
				}
			}
		}
	}
	return false
}

func transferTSIGConfigs(cfg *Config, zoneTSIG *TSIGZoneConfig) []*TSIGZoneConfig {
	var out []*TSIGZoneConfig
	if zoneTSIG != nil {
		out = append(out, zoneTSIG)
	}
	if d := discoveryTSIG(cfg); d != nil && d != zoneTSIG {
		out = append(out, d)
	}
	return out
}

func discoveryTSIG(cfg *Config) *TSIGZoneConfig {
	if cfg == nil || cfg.Discovery == nil {
		return nil
	}
	return cfg.Discovery.TSIG
}

func allowXFRFromMatches(ip net.IP, allow string) bool {
	if ip == nil {
		return false
	}
	allow = strings.TrimSpace(allow)
	if allow == "" {
		return false
	}
	if strings.Contains(allow, "/") {
		_, n, err := net.ParseCIDR(allow)
		return err == nil && n.Contains(ip)
	}
	return ip.Equal(net.ParseIP(allow))
}

func (a *authority) xfr(w dns.ResponseWriter, r *dns.Msg, ixfr bool) {
	if !a.xfrAllowed(w, r) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		if ts := r.IsTsig(); ts != nil {
			m.SetTsig(ts.Hdr.Name, ts.Algorithm, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(m)
		_ = w.Close()
		return
	}
	tr := &dns.Transfer{}
	ch := make(chan *dns.Envelope)
	go func() {
		soa := a.soa()
		if ixfr {
			if len(r.Ns) > 0 {
				if rr, ok := r.Ns[0].(*dns.SOA); ok {
					if rr.Serial >= a.serial {
						ch <- &dns.Envelope{RR: []dns.RR{soa}}
						close(ch)
						return
					}
					if a.ixfr != nil && rr.Serial == a.ixfr.old.Serial {
						rrset := append([]dns.RR{a.ixfr.old}, a.ixfr.del...)
						rrset = append(rrset, a.ixfr.new)
						rrset = append(rrset, a.ixfr.add...)
						ch <- &dns.Envelope{RR: rrset}
						close(ch)
						return
					}
					log.Printf("ixfr diff unavailable for %s from serial %d; sending AXFR", a.zone.Name, rr.Serial)
				}
			}
		}
		records := a.axfrRecords()
		ch <- &dns.Envelope{RR: []dns.RR{soa}}
		for len(records) > 0 {
			end := 500
			if end > len(records) {
				end = len(records)
			}
			ch <- &dns.Envelope{RR: records[:end]}
			records = records[end:]
		}
		ch <- &dns.Envelope{RR: []dns.RR{soa}}
		close(ch)
	}()
	if err := tr.Out(w, r, ch); err != nil {
		log.Printf("xfr for %s failed: %v", a.zone.Name, err)
	}
	_ = w.Close()
}

func (a *authority) axfrRecords() []dns.RR {
	if strings.ToLower(a.zone.Serve) == "secondary" {
		a.mu.RLock()
		defer a.mu.RUnlock()
		out := make([]dns.RR, len(a.axfrRRs))
		copy(out, a.axfrRRs)
		return out
	}
	var rrs []dns.RR
	z := ensureDot(a.zone.Name)
	for _, ns := range a.zone.NS {
		rrs = append(rrs, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
	}
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAMaster))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAStandby))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAFallback))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAMasterPrivate))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAStandbyPrivate))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAFallbackPrivate))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AMaster))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AStandby))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AFallback))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AMasterPrivate))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AStandbyPrivate))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AFallbackPrivate))...)
	for _, h := range a.zone.Hosts {
		owner := hostOwnerName(a.zone.Name, h.Name)
		var aaaaAddrs, aAddrs []string
		for _, p := range h.Pools {
			switch strings.ToLower(strings.TrimSpace(p.Family)) {
			case "ipv6":
				aaaaAddrs = append(aaaaAddrs, config.IPsFrom(p.Members)...)
			case "ipv4":
				aAddrs = append(aAddrs, config.IPsFrom(p.Members)...)
			}
		}
		rrs = append(rrs, buildAAAAForOwner(owner, a.zone.TTLAnswer, aaaaAddrs, a.cfg.MaxRecords, a.cfg.EDNSBuf)...)
		rrs = append(rrs, buildAForOwner(owner, a.zone.TTLAnswer, aAddrs, a.cfg.MaxRecords, a.cfg.EDNSBuf)...)
	}
	for _, t := range a.zone.TXT {
		name := ownerName(a.zone.Name, t.Name)
		ttl := t.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		if len(t.Text) > 0 {
			rrs = append(rrs, &dns.TXT{Hdr: hdr(name, dns.TypeTXT, ttl), Txt: t.Text})
		}
	}
	for _, mx := range a.zone.MX {
		name := ownerName(a.zone.Name, mx.Name)
		ttl := mx.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.MX{Hdr: hdr(name, dns.TypeMX, ttl), Preference: mx.Preference, Mx: ensureDot(mx.Exchange)})
	}
	for _, c := range a.zone.CAA {
		name := ownerName(a.zone.Name, c.Name)
		ttl := c.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.CAA{Hdr: hdr(name, dns.TypeCAA, ttl), Flag: c.Flag, Tag: c.Tag, Value: c.Value})
	}
	if a.zone.RP != nil {
		name := ownerName(a.zone.Name, a.zone.RP.Name)
		ttl := a.zone.RP.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.RP{Hdr: hdr(name, dns.TypeRP, ttl), Mbox: ensureDot(a.zone.RP.Mbox), Txt: ensureDot(a.zone.RP.Txt)})
	}
	for _, s := range a.zone.SSHFP {
		name := ownerName(a.zone.Name, s.Name)
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SSHFP{Hdr: hdr(name, dns.TypeSSHFP, ttl), Algorithm: s.Algorithm, Type: s.Type, FingerPrint: s.Fingerprint})
	}
	for _, s := range a.zone.SRV {
		name := ownerName(a.zone.Name, s.Name)
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SRV{Hdr: hdr(name, dns.TypeSRV, ttl), Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: ensureDot(s.Target)})
	}
	for _, n := range a.zone.NAPTR {
		name := ownerName(a.zone.Name, n.Name)
		ttl := n.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.NAPTR{Hdr: hdr(name, dns.TypeNAPTR, ttl), Order: n.Order, Preference: n.Preference, Flags: n.Flags, Service: n.Services, Regexp: n.Regexp, Replacement: ensureDot(n.Replacement)})
	}
	for _, p := range a.zone.PTR {
		name := ownerName(a.zone.Name, p.Name)
		ttl := p.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.PTR{Hdr: hdr(name, dns.TypePTR, ttl), Ptr: ensureDot(p.PTR)})
	}
	if a.keys == nil || !a.keys.enabled {
		out := rrs
		rrs = nil
		return out
	}
	rrs = append(rrs, a.dnskeyRRSet()...)
	if a.keys.nsec3Iterations > 0 {
		if nsec3param := a.makeNSEC3PARAM(); nsec3param != nil {
			rrs = append(rrs, nsec3param)
		}
		seen := map[string]bool{}
		for _, owner := range a.zidx.names {
			nsec3 := a.makeNSEC3(owner)
			if nsec3 == nil {
				continue
			}
			key := strings.ToLower(nsec3.Hdr.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			rrs = append(rrs, nsec3)
		}
	} else {
		for _, owner := range a.zidx.names {
			if nsec := a.makeNSEC(owner); nsec != nil {
				rrs = append(rrs, nsec)
			}
		}
	}
	rrs = a.signAll(rrs)
	rrs = append(rrs, a.rrsetSignatures([]dns.RR{a.soa()})...)
	out := rrs
	rrs = nil
	return out
}

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

// Address selection for a given owner name
func (a *authority) addrA(owner string, src net.IP, r *dns.Msg) []dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	zone := strings.ToLower(ensureDot(a.zone.Name))
	if rr, ok := a.hostAddressAnswers(owner, src, false); ok {
		return rr
	}
	if strings.HasSuffix(owner, zone) {
		host := strings.TrimSuffix(owner, zone)
		host = strings.TrimSuffix(host, ".")
		if host != "" {
			if tgt, ok := a.zone.AliasHost[strings.ToLower(host)]; ok {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
				defer cancel()
				ips := aliasLookup(ctx, tgt)
				var addrs []string
				for _, ip := range ips {
					if ip.To4() != nil {
						addrs = append(addrs, ip.String())
					}
				}
				if len(addrs) > 0 {
					return a.persistRR(a.buildA(addrs), src, false)
				}
				return nil
			}
		}
	}
	if owner != zone {
		return a.lightupARecords(owner, src)
	}
	// local view first if enabled
	if strings.ToLower(a.zone.Serve) == "local" && src != nil {
		if rr := a.localAnswers(false /*v6*/, src); rr != nil {
			return a.persistRR(rr, src, false)
		}
	}
	// Geo answer overrides (per country/continent) if configured
	if src != nil {
		if rr := a.answersByGeo(owner, src, false); rr != nil {
			return a.persistRR(rr, src, false)
		}
	}
	if len(a.zone.Pools) > 0 {
		if src != nil {
			if pool := a.pickTierByGeo(src, false); pool != "" {
				if rr := a.poolAnswersByName(pool, false); rr != nil {
					return a.persistRR(rr, src, false)
				}
			}
		}
		if rr := a.publicPoolAnswers(false); rr != nil {
			return a.persistRR(rr, src, false)
		}
	}
	// Geo steering (policy-only) if configured
	if src != nil {
		if tier := a.pickTierByGeo(src, false); tier != "" {
			return a.persistRR(a.publicFor(tier, false), src, false)
		}
	}
	// public flow: master -> standby -> fallback
	mV4, _, sV4, _ := a.state.snapshot()
	var addrs []string
	if mV4 && len(a.zone.AMaster) > 0 {
		addrs = config.IPsFrom(a.zone.AMaster)
	} else if sV4 && len(a.zone.AStandby) > 0 {
		addrs = config.IPsFrom(a.zone.AStandby)
	} else if len(a.zone.AFallback) > 0 {
		addrs = config.IPsFrom(a.zone.AFallback)
	} else if a.zone.Alias != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
		defer cancel()
		ips := aliasLookup(ctx, a.zone.Alias)
		for _, ip := range ips {
			if ip.To4() != nil {
				addrs = append(addrs, ip.String())
			}
		}
	}
	return a.persistRR(a.buildA(addrs), src, false)
}

func (a *authority) addrAAAA(owner string, src net.IP, r *dns.Msg) []dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	zone := strings.ToLower(ensureDot(a.zone.Name))
	if rr, ok := a.hostAddressAnswers(owner, src, true); ok {
		return rr
	}
	if strings.HasSuffix(owner, zone) {
		host := strings.TrimSuffix(owner, zone)
		host = strings.TrimSuffix(host, ".")
		if host != "" {
			if tgt, ok := a.zone.AliasHost[strings.ToLower(host)]; ok {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
				defer cancel()
				ips := aliasLookup(ctx, tgt)
				var addrs []string
				for _, ip := range ips {
					if ip.To4() == nil {
						addrs = append(addrs, ip.String())
					}
				}
				if len(addrs) > 0 {
					return a.persistRR(a.buildAAAA(addrs), src, true)
				}
				return nil
			}
		}
	}
	if owner != zone {
		return a.lightupAAAARecords(owner, src)
	}
	if strings.ToLower(a.zone.Serve) == "local" && src != nil {
		if rr := a.localAnswers(true /*v6*/, src); rr != nil {
			return a.persistRR(rr, src, true)
		}
	}
	// Geo answer overrides first
	if src != nil {
		if rr := a.answersByGeo(owner, src, true); rr != nil {
			return a.persistRR(rr, src, true)
		}
	}
	if len(a.zone.Pools) > 0 {
		if src != nil {
			if pool := a.pickTierByGeo(src, true); pool != "" {
				if rr := a.poolAnswersByName(pool, true); rr != nil {
					return a.persistRR(rr, src, true)
				}
			}
		}
		if rr := a.publicPoolAnswers(true); rr != nil {
			return a.persistRR(rr, src, true)
		}
	}
	// Policy-only geo if any
	if src != nil {
		if tier := a.pickTierByGeo(src, true); tier != "" {
			return a.persistRR(a.publicFor(tier, true), src, true)
		}
	}
	_, mV6, _, sV6 := a.state.snapshot()
	var addrs []string
	if mV6 && len(a.zone.AAAAMaster) > 0 {
		addrs = config.IPsFrom(a.zone.AAAAMaster)
	} else if sV6 && len(a.zone.AAAAStandby) > 0 {
		addrs = config.IPsFrom(a.zone.AAAAStandby)
	} else if len(a.zone.AAAAFallback) > 0 {
		addrs = config.IPsFrom(a.zone.AAAAFallback)
	} else if a.zone.Alias != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
		defer cancel()
		ips := aliasLookup(ctx, a.zone.Alias)
		for _, ip := range ips {
			if ip.To4() == nil {
				addrs = append(addrs, ip.String())
			}
		}
	}
	if len(addrs) == 0 && src != nil && src.To4() == nil && a.cfg.DNS64Prefix != "" {
		prefix := net.ParseIP(a.cfg.DNS64Prefix)
		if prefix != nil {
			var rrs []dns.RR
			for _, rr := range a.addrA(owner, src, r) {
				if aRec, ok := rr.(*dns.A); ok {
					v6 := make(net.IP, net.IPv6len)
					copy(v6[:12], prefix.To16()[:12])
					copy(v6[12:], aRec.A.To4())
					rrs = append(rrs, &dns.AAAA{Hdr: hdr(ensureDot(owner), dns.TypeAAAA, a.zone.TTLAnswer), AAAA: v6})
				}
			}
			if len(rrs) > 0 {
				return rrs
			}
		}
	}
	if len(addrs) == 0 {
		return a.lightupAAAARecords(owner, src)
	}
	return a.persistRR(a.buildAAAA(addrs), src, true)
}

func (a *authority) hostAddressAnswers(owner string, src net.IP, ipv6 bool) ([]dns.RR, bool) {
	h := a.serviceHost(owner)
	if h == nil {
		return nil, false
	}
	st := a.serviceState(owner)
	if h.Alias != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
		defer cancel()
		ips := aliasLookup(ctx, h.Alias)
		var addrs []string
		for _, ip := range ips {
			if ipv6 && ip.To4() == nil {
				addrs = append(addrs, ip.String())
			}
			if !ipv6 && ip.To4() != nil {
				addrs = append(addrs, ip.String())
			}
		}
		if ipv6 {
			return buildAAAAForOwner(owner, a.zone.TTLAnswer, addrs, a.cfg.MaxRecords, a.cfg.EDNSBuf), true
		}
		return buildAForOwner(owner, a.zone.TTLAnswer, addrs, a.cfg.MaxRecords, a.cfg.EDNSBuf), true
	}
	if strings.ToLower(a.zone.Serve) == "local" && src != nil {
		if rr := a.privatePoolAnswersWithState(h.Pools, st, ipv6, src); rr != nil {
			return reownerRRs(owner, rr), true
		}
	}
	if len(h.Pools) == 0 {
		return nil, true
	}
	geo := h.Geo
	if geo == nil {
		geo = a.zone.Geo
	}
	if src != nil && geo != nil {
		if len(geo.Named) > 0 {
			if cc, cont, ok := countryContinent(a.geo, src); ok {
				if pool := a.pickPoolByGeoFrom(geo, h.Pools, cc, cont, ipv6); pool != "" {
					if rr := a.poolAnswersByNameWithState(h.Pools, st, pool, ipv6); rr != nil {
						return reownerRRs(owner, rr), true
					}
				}
			}
		} else if tier := a.pickTargetByGeo(geo, h.Pools, src, ipv6); tier != "" {
			if rr := a.publicPoolAnswersByRoleWithState(h.Pools, st, tier, ipv6); rr != nil {
				return reownerRRs(owner, rr), true
			}
		}
	}
	if rr := a.publicPoolAnswersWithState(h.Pools, st, ipv6); rr != nil {
		return reownerRRs(owner, rr), true
	}
	return nil, true
}

func countryContinent(gr *geoResolver, src net.IP) (string, string, bool) {
	if gr == nil || src == nil {
		return "", "", false
	}
	return gr.lookup(src)
}

func reownerRRs(owner string, rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(rrs))
	owner = ensureDot(owner)
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			cp := *v
			cp.Hdr.Name = owner
			out = append(out, &cp)
		case *dns.AAAA:
			cp := *v
			cp.Hdr.Name = owner
			out = append(out, &cp)
		default:
			out = append(out, dns.Copy(rr))
		}
	}
	return out
}

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

func (a *authority) persistRR(rrs []dns.RR, src net.IP, ipv6 bool) []dns.RR {
	if src == nil {
		return rrs
	}
	enabled := a.cfg.PersistenceEnabled || a.zone.PersistenceEnabled
	if !enabled || len(rrs) <= 1 {
		return rrs
	}
	mode := a.cfg.PersistenceMode
	if a.zone.PersistenceMode != "" {
		mode = a.zone.PersistenceMode
	}
	ttl := time.Duration(a.zone.TTLAnswer) * time.Second
	key := src.String()
	now := time.Now()
	var store *sync.Map
	var ctr *atomic.Uint64
	var build func([]string) []dns.RR
	if ipv6 {
		store = &a.persistAAAA
		ctr = &a.rrAAAA
		build = a.buildAAAA
	} else {
		store = &a.persistA
		ctr = &a.rrA
		build = a.buildA
	}
	if val, ok := store.Load(key); ok {
		pv := val.(persistEntry)
		if now.Before(pv.exp) {
			return build([]string{pv.ip})
		}
		store.Delete(key)
	}
	addrs := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if ipv6 {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				addrs = append(addrs, aaaa.AAAA.String())
			}
		} else {
			if aRec, ok := rr.(*dns.A); ok {
				addrs = append(addrs, aRec.A.String())
			}
		}
	}
	if len(addrs) <= 1 {
		return rrs
	}
	ip := pickAddr(addrs, mode, ctr)
	if ip == "" {
		return rrs
	}
	store.Store(key, persistEntry{ip: ip, exp: now.Add(ttl)})
	return build([]string{ip})
}

func (a *authority) buildA(addrs []string) []dns.RR {
	return buildAForOwner(a.zone.Name, a.zone.TTLAnswer, addrs, a.cfg.MaxRecords, a.cfg.EDNSBuf)
}

func buildAForOwner(owner string, ttl uint32, addrs []string, maxRecords, ednsBuf int) []dns.RR {
	var (
		rrs []dns.RR
		m   dns.Msg
	)
	for _, ip := range addrs {
		p := net.ParseIP(ip)
		if p == nil || p.To4() == nil {
			continue
		}
		rr := &dns.A{Hdr: hdr(ensureDot(owner), dns.TypeA, ttl), A: p.To4()}
		candidate := append(rrs, rr)
		if maxRecords > 0 && len(candidate) > maxRecords {
			break
		}
		m.Answer = candidate
		if ednsBuf > 0 && m.Len() > ednsBuf {
			break
		}
		rrs = candidate
	}
	return rrs
}

func (a *authority) buildAAAA(addrs []string) []dns.RR {
	return buildAAAAForOwner(a.zone.Name, a.zone.TTLAnswer, addrs, a.cfg.MaxRecords, a.cfg.EDNSBuf)
}

func buildAAAAForOwner(owner string, ttl uint32, addrs []string, maxRecords, ednsBuf int) []dns.RR {
	var (
		rrs []dns.RR
		m   dns.Msg
	)
	for _, ip := range addrs {
		p := net.ParseIP(ip)
		if p == nil || p.To4() != nil {
			continue
		}
		rr := &dns.AAAA{Hdr: hdr(ensureDot(owner), dns.TypeAAAA, ttl), AAAA: p}
		candidate := append(rrs, rr)
		if maxRecords > 0 && len(candidate) > maxRecords {
			break
		}
		m.Answer = candidate
		if ednsBuf > 0 && m.Len() > ednsBuf {
			break
		}
		rrs = candidate
	}
	return rrs
}

// Shared/static helpers
func (a *authority) txtFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, t := range a.zone.TXT {
		name := ownerName(a.zone.Name, t.Name)
		if name != owner {
			continue
		}
		ttl := t.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		if len(t.Text) > 0 {
			rrs = append(rrs, &dns.TXT{Hdr: hdr(name, dns.TypeTXT, ttl), Txt: t.Text})
		}
	}
	return rrs
}

func (a *authority) mxFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, mx := range a.zone.MX {
		name := ownerName(a.zone.Name, mx.Name)
		if name != owner {
			continue
		}
		ttl := mx.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.MX{Hdr: hdr(name, dns.TypeMX, ttl), Preference: mx.Preference, Mx: ensureDot(mx.Exchange)})
	}
	return rrs
}

func (a *authority) caaFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, c := range a.zone.CAA {
		name := ownerName(a.zone.Name, c.Name)
		if name != owner {
			continue
		}
		ttl := c.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.CAA{Hdr: hdr(name, dns.TypeCAA, ttl), Flag: c.Flag, Tag: c.Tag, Value: c.Value})
	}
	return rrs
}

func (a *authority) rpFor(owner string) dns.RR {
	owner = ensureDot(owner)
	if a.zone.RP == nil {
		return nil
	}
	name := ownerName(a.zone.Name, a.zone.RP.Name)
	if name != owner {
		return nil
	}
	ttl := a.zone.RP.TTL
	if ttl == 0 {
		ttl = a.zone.TTLAnswer
	}
	return &dns.RP{Hdr: hdr(name, dns.TypeRP, ttl), Mbox: ensureDot(a.zone.RP.Mbox), Txt: ensureDot(a.zone.RP.Txt)}
}

func (a *authority) sshfpFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, s := range a.zone.SSHFP {
		name := ownerName(a.zone.Name, s.Name)
		if name != owner {
			continue
		}
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SSHFP{Hdr: hdr(name, dns.TypeSSHFP, ttl), Algorithm: s.Algorithm, Type: s.Type, FingerPrint: s.Fingerprint})
	}
	return rrs
}

func (a *authority) srvFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, s := range a.zone.SRV {
		name := ownerName(a.zone.Name, s.Name)
		if name != owner {
			continue
		}
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SRV{Hdr: hdr(name, dns.TypeSRV, ttl), Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: ensureDot(s.Target)})
	}
	return rrs
}

func (a *authority) naptrFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, n := range a.zone.NAPTR {
		name := ownerName(a.zone.Name, n.Name)
		if name != owner {
			continue
		}
		ttl := n.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.NAPTR{Hdr: hdr(name, dns.TypeNAPTR, ttl), Order: n.Order, Preference: n.Preference, Flags: n.Flags, Service: n.Services, Regexp: n.Regexp, Replacement: ensureDot(n.Replacement)})
	}
	return rrs
}

func (a *authority) ptrFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, p := range a.zone.PTR {
		name := ownerName(a.zone.Name, p.Name)
		if name != owner {
			continue
		}
		ttl := p.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.PTR{Hdr: hdr(name, dns.TypePTR, ttl), Ptr: ensureDot(p.PTR)})
	}
	if len(rrs) > 0 {
		return rrs
	}
	if rr := a.lightupPTRRecord(owner); rr != nil {
		rrs = append(rrs, rr)
	}
	return rrs
}

func (a *authority) authoritativeNameExists(name string) bool {
	if a.zidx != nil && a.zidx.hasName(name) {
		return true
	}
	return a.runtimeNameExists(name)
}

func (a *authority) secondaryRRSIGs(owner string, covered uint16) []dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	var out []dns.RR
	for _, rr := range a.records[owner] {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig.TypeCovered != covered {
			continue
		}
		out = append(out, sig)
	}
	return out
}

func (a *authority) secondaryDenialProofs(name string, missing bool, src net.IP, r *dns.Msg) []dns.RR {
	if a.zidx == nil {
		return nil
	}
	var out []dns.RR
	if a.secondaryNSEC3Iterations() > 0 {
		var proofs []dns.RR
		if missing {
			proofs = a.nsec3DenialProofs(name)
		} else if nsec3 := a.makeNSEC3ForQuery(name, src, r); nsec3 != nil {
			proofs = append(proofs, nsec3)
		}
		for _, rr := range proofs {
			out = append(out, rr)
			out = append(out, a.secondaryRRSIGs(rr.Header().Name, rr.Header().Rrtype)...)
		}
		return out
	}
	if missing {
		nsecMap := map[string]*dns.NSEC{}
		var order []string
		add := func(owner string) {
			if n := a.makeNSEC(owner); n != nil {
				ns := n.(*dns.NSEC)
				key := strings.ToLower(ns.Hdr.Name) + "|" + strings.ToLower(ns.NextDomain)
				if _, ok := nsecMap[key]; ok {
					return
				}
				nsecMap[key] = ns
				order = append(order, key)
			}
		}
		add(a.zidx.prevName(name))
		if closest := a.zidx.closestEncloser(name); closest != "" {
			add(a.zidx.prevName("*." + closest))
		}
		for _, key := range order {
			rr := nsecMap[key]
			out = append(out, rr)
			out = append(out, a.secondaryRRSIGs(rr.Header().Name, dns.TypeNSEC)...)
		}
		return out
	}
	if nsec := a.makeNSECForQuery(name, src, r); nsec != nil {
		out = append(out, nsec)
		out = append(out, a.secondaryRRSIGs(nsec.Header().Name, dns.TypeNSEC)...)
	}
	return out
}

func (a *authority) secondaryDNSSECAvailable() bool {
	return a.zone.DNSSEC != nil && a.zone.DNSSEC.Mode != "" && a.zone.DNSSEC.Mode != DNSSECModeOff
}

func (a *authority) secondaryNSEC3Iterations() uint16 {
	if a.keys != nil && a.keys.nsec3Iterations > 0 {
		return a.keys.nsec3Iterations
	}
	if a.zone.DNSSEC != nil {
		return a.zone.DNSSEC.NSEC3Iterations
	}
	return 0
}

func (a *authority) runtimeNameExists(name string) bool {
	return len(a.runtimeNameTypes(name)) > 0
}

func wantDNSSEC(r *dns.Msg) bool {
	if o := r.IsEdns0(); o != nil {
		return o.Do()
	}
	return false
}
