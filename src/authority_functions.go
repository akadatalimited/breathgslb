package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/akadatalimited/breathgslb/src/healthcheck"
	"github.com/miekg/dns"
)

// Authority-related functions

func (a *authority) fetchLoop() {
	var expire time.Time
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}
		if err := a.transferFromMasters(); err != nil {
			log.Printf("xfr fetch for %s failed: %v", a.zone.Name, err)
			retry := time.Duration(a.zone.Retry) * time.Second
			if retry <= 0 {
				retry = time.Minute
			}
			if !expire.IsZero() && time.Now().After(expire) {
				a.mu.Lock()
				a.records = nil
				a.axfrRRs = nil
				a.soaRR = nil
				a.mu.Unlock()
			}
			select {
			case <-time.After(retry):
			case <-a.ctx.Done():
				return
			}
		} else {
			expire = time.Now().Add(time.Duration(a.zone.Expire) * time.Second)
			refresh := time.Duration(a.zone.Refresh) * time.Second
			if refresh <= 0 {
				refresh = 5 * time.Minute
			}
			select {
			case <-time.After(refresh):
			case <-a.ctx.Done():
				return
			}
		}
	}
}

func (a *authority) transferFromMasters() error {
	var lastErr error
	for _, master := range a.zone.Masters {
		addr := master
		if !strings.Contains(addr, ":") || strings.HasSuffix(addr, "]") {
			addr = net.JoinHostPort(addr, "53")
		}
		m := new(dns.Msg)
		m.SetAxfr(a.zone.Name)
		var tr *dns.Transfer
		if a.zone.TSIG != nil && len(a.zone.TSIG.Keys) > 0 {
			k := a.zone.TSIG.Keys[0]
			name := ensureDot(k.Name)
			alg := k.Algorithm
			if alg == "" {
				alg = dns.HmacSHA256
			}
			tr = &dns.Transfer{TsigSecret: map[string]string{name: k.Secret}}
			m.SetTsig(name, alg, 300, time.Now().Unix())
		} else {
			tr = &dns.Transfer{}
		}
		env, err := tr.In(m, addr)
		if err != nil {
			lastErr = err
			continue
		}
		var all []dns.RR
		for e := range env {
			if e.Error != nil {
				err = e.Error
				break
			}
			all = append(all, e.RR...)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if len(all) < 2 {
			lastErr = fmt.Errorf("empty xfr")
			continue
		}
		startSOA, ok := all[0].(*dns.SOA)
		if !ok {
			lastErr = fmt.Errorf("first record not SOA")
			continue
		}
		endSOA, ok := all[len(all)-1].(*dns.SOA)
		if !ok {
			lastErr = fmt.Errorf("last record not SOA")
			continue
		}
		records := all[1 : len(all)-1]
		recMap := make(map[string][]dns.RR)
		nsList := []string{}
		for _, rr := range records {
			name := strings.ToLower(ensureDot(rr.Header().Name))
			recMap[name] = append(recMap[name], rr)
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ensureDot(ns.Hdr.Name), ensureDot(a.zone.Name)) {
				nsList = append(nsList, ensureDot(ns.Ns))
			}
		}
		a.mu.Lock()
		a.records = recMap
		a.axfrRRs = records
		a.soaRR = endSOA
		a.serial = endSOA.Serial
		a.zone.NS = nsList
		a.zone.Refresh = startSOA.Refresh
		a.zone.Retry = startSOA.Retry
		a.zone.Expire = startSOA.Expire
		a.zone.Admin = startSOA.Mbox
		a.zone.TTLSOA = startSOA.Hdr.Ttl
		a.zone.Minttl = startSOA.Minttl
		a.zidx = buildIndexFromRRs(a.zone.Name, records)
		a.mu.Unlock()
		return nil
	}
	return lastErr
}

func (a *authority) purgeLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			a.persistA.Range(func(k, v any) bool {
				if now.After(v.(persistEntry).exp) {
					a.persistA.Delete(k)
				}
				return true
			})
			a.persistAAAA.Range(func(k, v any) bool {
				if now.After(v.(persistEntry).exp) {
					a.persistAAAA.Delete(k)
				}
				return true
			})
		case <-a.ctx.Done():
			return
		}
	}
}

// localAnswers decides per-tier private/public answers for local sources.
func (a *authority) localAnswers(ipv6 bool, src net.IP) []dns.RR {
	// tier order master -> standby -> fallback
	if a.isLocal("master", src) {
		// if isolated and allowed, serve private regardless of health
		if a.zone.PrivateAllowWhenIsolated || a.tierUp("master", ipv6) {
			if rr := a.privateFor("master", ipv6); rr != nil {
				return rr
			}
			return a.publicFor("master", ipv6)
		}
	}
	if a.isLocal("standby", src) {
		if a.zone.PrivateAllowWhenIsolated || a.tierUp("standby", ipv6) {
			if rr := a.privateFor("standby", ipv6); rr != nil {
				return rr
			}
			return a.publicFor("standby", ipv6)
		}
	}
	if a.isLocal("fallback", src) {
		if a.zone.PrivateAllowWhenIsolated || true { // fallback assumed available
			if rr := a.privateFor("fallback", ipv6); rr != nil {
				return rr
			}
			return a.publicFor("fallback", ipv6)
		}
	}
	return nil
}

func (a *authority) tierUp(tier string, ipv6 bool) bool {
	mV4, mV6, sV4, sV6 := a.state.snapshot()
	switch tier {
	case "master":
		if ipv6 {
			return mV6
		}
		return mV4
	case "standby":
		if ipv6 {
			return sV6
		}
		return sV4
	default:
		return true // fallback assumed available
	}
}

// setMasterUp marks the master tier's up state for both address families.
// It acquires the state's mutex; tests should call this helper instead of
// manipulating state.master directly.
func (a *authority) setMasterUp(v4, v6 bool) {
	a.state.mu.Lock()
	a.state.master.v4.up = v4
	a.state.master.v6.up = v6
	a.state.mu.Unlock()
}

func (a *authority) privateFor(tier string, ipv6 bool) []dns.RR {
	switch tier {
	case "master":
		if !ipv6 && len(a.zone.AMasterPrivate) > 0 {
			return a.buildA(config.IPsFrom(a.zone.AMasterPrivate))
		}
		if ipv6 && len(a.zone.AAAAMasterPrivate) > 0 {
			return a.buildAAAA(config.IPsFrom(a.zone.AAAAMasterPrivate))
		}
	case "standby":
		if !ipv6 && len(a.zone.AStandbyPrivate) > 0 {
			return a.buildA(config.IPsFrom(a.zone.AStandbyPrivate))
		}
		if ipv6 && len(a.zone.AAAAStandbyPrivate) > 0 {
			return a.buildAAAA(config.IPsFrom(a.zone.AAAAStandbyPrivate))
		}
	case "fallback":
		if !ipv6 && len(a.zone.AFallbackPrivate) > 0 {
			return a.buildA(config.IPsFrom(a.zone.AFallbackPrivate))
		}
		if ipv6 && len(a.zone.AAAAFallbackPrivate) > 0 {
			return a.buildAAAA(config.IPsFrom(a.zone.AAAAFallbackPrivate))
		}
	}
	return nil
}

func (a *authority) publicFor(tier string, ipv6 bool) []dns.RR {
	switch tier {
	case "master":
		if !ipv6 {
			return a.buildA(config.IPsFrom(a.zone.AMaster))
		}
		return a.buildAAAA(config.IPsFrom(a.zone.AAAAMaster))
	case "standby":
		if !ipv6 {
			return a.buildA(config.IPsFrom(a.zone.AStandby))
		}
		return a.buildAAAA(config.IPsFrom(a.zone.AAAAStandby))
	default:
		if !ipv6 {
			return a.buildA(config.IPsFrom(a.zone.AFallback))
		}
		return a.buildAAAA(config.IPsFrom(a.zone.AAAAFallback))
	}
}

func (a *authority) cidrInit() {
	parseAll := func(cidrs []string) []*net.IPNet {
		var out []*net.IPNet
		for _, s := range cidrs {
			_, n, err := net.ParseCIDR(strings.TrimSpace(s))
			if err == nil && n != nil {
				out = append(out, n)
			}
		}
		return out
	}
	// per-tier local ranges
	a.cidrs.master.rfc = parseAll(a.zone.RFCMaster)
	a.cidrs.master.ula = parseAll(a.zone.ULAMaster)
	a.cidrs.standby.rfc = parseAll(a.zone.RFCStandby)
	a.cidrs.standby.ula = parseAll(a.zone.ULAStandby)
	a.cidrs.fallback.rfc = parseAll(a.zone.RFCFallback)
	a.cidrs.fallback.ula = parseAll(a.zone.ULAFallback)

	// geo_answers CIDRs
	a.geoCIDR.country = map[string]parsedCIDRs{}
	a.geoCIDR.continent = map[string]parsedCIDRs{}
	if a.zone.GeoAnswers != nil {
		for k, set := range a.zone.GeoAnswers.Country {
			kk := strings.ToUpper(strings.TrimSpace(k))
			a.geoCIDR.country[kk] = parsedCIDRs{rfc: parseAll(set.RFC), ula: parseAll(set.ULA)}
		}
		for k, set := range a.zone.GeoAnswers.Continent {
			kk := strings.ToUpper(strings.TrimSpace(k))
			a.geoCIDR.continent[kk] = parsedCIDRs{rfc: parseAll(set.RFC), ula: parseAll(set.ULA)}
		}
	}
}

func (a *authority) isLocal(tier string, ip net.IP) bool {
	inAny := func(nets []*net.IPNet) bool {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	switch tier {
	case "master":
		return inAny(a.cidrs.master.rfc) || inAny(a.cidrs.master.ula)
	case "standby":
		return inAny(a.cidrs.standby.rfc) || inAny(a.cidrs.standby.ula)
	default:
		return inAny(a.cidrs.fallback.rfc) || inAny(a.cidrs.fallback.ula)
	}
}

// Geo steering helpers
func (a *authority) pickTierByGeo(src net.IP, ipv6 bool) string {
	if a.geo == nil || a.zone.Geo == nil || src == nil {
		return ""
	}
	cc, cont, ok := a.geo.lookup(src)
	if !ok {
		return ""
	}
	// Check in order: master -> standby -> fallback, but only if policy allows
	check := func(tier string, famV6 bool) bool {
		if !a.policyAllows(tier, cc, cont) {
			return false
		}
		// also require health for master/standby
		if tier == "fallback" {
			return true
		}
		return a.tierUp(tier, famV6)
	}
	if check("master", ipv6) {
		return "master"
	}
	if check("standby", ipv6) {
		return "standby"
	}
	if a.policyAllows("fallback", cc, cont) {
		return "fallback"
	}
	return ""
}

func (a *authority) policyAllows(tier string, country, continent string) bool {
	g := a.zone.Geo
	if g == nil {
		return false
	}
	var tp GeoTierPolicy
	switch tier {
	case "master":
		tp = g.Master
	case "standby":
		tp = g.Standby
	default:
		tp = g.Fallback
	}
	if tp.AllowAll {
		return true
	}
	country = strings.ToUpper(strings.TrimSpace(country))
	continent = strings.ToUpper(strings.TrimSpace(continent))
	contains := func(list []string, v string) bool {
		for _, x := range list {
			if strings.ToUpper(strings.TrimSpace(x)) == v {
				return true
			}
		}
		return false
	}
	if len(tp.AllowCountries) > 0 && contains(tp.AllowCountries, country) {
		return true
	}
	if len(tp.AllowContinents) > 0 && contains(tp.AllowContinents, continent) {
		return true
	}
	return false
}

// Geo answer overrides
func (a *authority) answersByGeo(owner string, src net.IP, ipv6 bool) []dns.RR {
	if a.geo == nil || a.zone.GeoAnswers == nil || src == nil {
		return nil
	}
	cc, cont, ok := a.geo.lookup(src)
	if !ok {
		return nil
	}
	cc = strings.ToUpper(cc)
	cont = strings.ToUpper(cont)
	// Country has priority over continent
	if s, ok := a.zone.GeoAnswers.Country[cc]; ok {
		if a.isLocalGeo(cc, true, src) { // true => country
			if ipv6 && len(s.AAAAPrivate) > 0 {
				return a.buildAAAA(s.AAAAPrivate)
			}
			if !ipv6 && len(s.APrivate) > 0 {
				return a.buildA(s.APrivate)
			}
		}
		if ipv6 && len(s.AAAA) > 0 {
			return a.buildAAAA(s.AAAA)
		}
		if !ipv6 && len(s.A) > 0 {
			return a.buildA(s.A)
		}
	}
	if s, ok := a.zone.GeoAnswers.Continent[cont]; ok {
		if a.isLocalGeo(cont, false, src) { // false => continent
			if ipv6 && len(s.AAAAPrivate) > 0 {
				return a.buildAAAA(s.AAAAPrivate)
			}
			if !ipv6 && len(s.APrivate) > 0 {
				return a.buildA(s.APrivate)
			}
		}
		if ipv6 && len(s.AAAA) > 0 {
			return a.buildAAAA(s.AAAA)
		}
		if !ipv6 && len(s.A) > 0 {
			return a.buildA(s.A)
		}
	}
	return nil
}

func inAnyCIDR(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *authority) isLocalGeo(key string, isCountry bool, ip net.IP) bool {
	if isCountry {
		p, ok := a.geoCIDR.country[key]
		if !ok {
			return false
		}
		return inAnyCIDR(ip, p.rfc) || inAnyCIDR(ip, p.ula)
	}
	p, ok := a.geoCIDR.continent[key]
	if !ok {
		return false
	}
	return inAnyCIDR(ip, p.rfc) || inAnyCIDR(ip, p.ula)
}

func (a *authority) soa() dns.RR {
	if strings.ToLower(a.zone.Serve) == "secondary" {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if a.soaRR != nil {
			rr := *a.soaRR
			return &rr
		}
	}
	z := ensureDot(a.zone.Name)
	nsPrimary := ensureDot(a.zone.NS[0])
	return &dns.SOA{Hdr: hdr(z, dns.TypeSOA, a.zone.TTLSOA), Ns: nsPrimary, Mbox: ensureDot(a.zone.Admin), Serial: a.serial, Refresh: a.zone.Refresh, Retry: a.zone.Retry, Expire: a.zone.Expire, Minttl: a.zone.Minttl}
}

func hdr(name string, t uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
}

func ensureDot(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

func ownerName(apex, s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == "@" {
		return ensureDot(apex)
	}
	return ensureDot(s)
}

// ---- health loop ----

func (a *authority) healthLoop() {
	base := time.Duration(a.cfg.IntervalSec) * time.Second
	if base <= 0 {
		base = 5 * time.Second
	}
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
			a.checkOnce()
			jitter := time.Duration(0)
			if a.cfg.JitterMs > 0 {
				jitter = time.Duration(rand.Intn(a.cfg.JitterMs+1)) * time.Millisecond
			}
			time.Sleep(base + jitter)
		}
	}
}

func (a *authority) checkOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
	defer cancel()

	hc := healthcheck.Effective(a.zone.Name, a.zone.Health)

	// master v4

	m4 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AMaster), hc)
	a.state.set("master", false, m4, a.cfg.Rise, a.cfg.Fall)
	// master v6
	m6 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AAAAMaster), hc)
	a.state.set("master", true, m6, a.cfg.Rise, a.cfg.Fall)
	// standby v4
	s4 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AStandby), hc)
	a.state.set("standby", false, s4, a.cfg.Rise, a.cfg.Fall)
	// standby v6
	s6 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AAAAStandby), hc)
	a.state.set("standby", true, s6, a.cfg.Rise, a.cfg.Fall)
}

