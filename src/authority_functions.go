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
		if a.zone.XFRSource != "" {
			srcIP := net.ParseIP(strings.TrimSpace(a.zone.XFRSource))
			if srcIP == nil {
				lastErr = fmt.Errorf("invalid xfr_source %q", a.zone.XFRSource)
				continue
			}
			dialer := &net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: srcIP}}
			conn, err := dialer.DialContext(a.ctx, "tcp", addr)
			if err != nil {
				lastErr = err
				continue
			}
			tr = &dns.Transfer{Conn: &dns.Conn{Conn: conn}}
		}
		if cfg := preferredTSIGConfig(a.zone.TSIG, discoveryTSIG(a.cfg)); cfg != nil {
			k := cfg.Keys[0]
			name := ensureDot(k.Name)
			alg := normalizeTSIGAlgorithm(k.Algorithm)
			if alg == "" {
				alg = dns.HmacSHA256
			}
			if tr == nil {
				tr = &dns.Transfer{}
			}
			tr.TsigSecret = map[string]string{name: k.Secret}
			m.SetTsig(name, alg, 300, time.Now().Unix())
		} else if tr == nil {
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
		if err := persistSecondarySnapshot(a.cfg, a.zone, records, endSOA); err != nil {
			log.Printf("persist secondary snapshot for %s failed: %v", a.zone.Name, err)
		}
		return nil
	}
	return lastErr
}

func normalizeTSIGAlgorithm(alg string) string {
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSpace(alg), ".")) {
	case "":
		return ""
	case "hmac-md5":
		return dns.HmacMD5
	case "hmac-sha1":
		return dns.HmacSHA1
	case "hmac-sha224":
		return dns.HmacSHA224
	case "hmac-sha256":
		return dns.HmacSHA256
	case "hmac-sha384":
		return dns.HmacSHA384
	case "hmac-sha512":
		return dns.HmacSHA512
	default:
		return alg
	}
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
	if len(a.zone.Pools) > 0 {
		if rr := a.privatePoolAnswersFrom(a.zone.Pools, ipv6, src); rr != nil {
			return rr
		}
	}
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
	if len(a.zone.Pools) > 0 {
		if rr := a.publicPoolAnswersByRoleFrom(a.zone.Pools, tier, ipv6); rr != nil {
			return rr
		}
	}
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

func (a *authority) publicPoolAnswersByRole(role string, ipv6 bool) []dns.RR {
	return a.publicPoolAnswersByRoleFrom(a.zone.Pools, role, ipv6)
}

func (a *authority) publicPoolAnswersByRoleFrom(pools []Pool, role string, ipv6 bool) []dns.RR {
	return a.publicPoolAnswersByRoleWithState(pools, a.state, role, ipv6)
}

func (a *authority) publicPoolAnswersByRoleWithState(pools []Pool, st *state, role string, ipv6 bool) []dns.RR {
	for _, p := range pools {
		if !a.poolMatches(&p, ipv6, "public") {
			continue
		}
		if !roleMatchesPool(role, p.Role) || !a.poolUpWithState(st, &p, ipv6) {
			continue
		}
		return a.buildPoolAnswers(&p, ipv6)
	}
	return nil
}

func (a *authority) buildPoolAnswers(p *Pool, ipv6 bool) []dns.RR {
	if p == nil {
		return nil
	}
	if ipv6 {
		return a.buildAAAA(config.IPsFrom(p.Members))
	}
	return a.buildA(config.IPsFrom(p.Members))
}

func (a *authority) poolMatches(p *Pool, ipv6 bool, class string) bool {
	if p == nil {
		return false
	}
	family := strings.ToLower(strings.TrimSpace(p.Family))
	wantFamily := "ipv4"
	if ipv6 {
		wantFamily = "ipv6"
	}
	if family != wantFamily {
		return false
	}
	if class == "" {
		return true
	}
	pClass := strings.ToLower(strings.TrimSpace(p.Class))
	if pClass == "" {
		pClass = "public"
	}
	return pClass == class
}

func roleMatchesPool(expected, actual string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	actual = strings.ToLower(strings.TrimSpace(actual))
	switch expected {
	case "master", "primary":
		return actual == "master" || actual == "primary"
	case "standby", "secondary":
		return actual == "standby" || actual == "secondary"
	case "fallback":
		return actual == "fallback"
	default:
		return expected == actual
	}
}

func (a *authority) poolUp(p *Pool, ipv6 bool) bool {
	return a.poolUpWithState(a.state, p, ipv6)
}

func (a *authority) poolUpWithState(st *state, p *Pool, ipv6 bool) bool {
	if p == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(p.Role)) {
	case "master", "primary":
		return tierUpState(st, "master", ipv6)
	case "standby", "secondary":
		return tierUpState(st, "standby", ipv6)
	default:
		return true
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
	return a.pickTargetByGeo(a.zone.Geo, a.zone.Pools, src, ipv6)
}

func (a *authority) pickTargetByGeo(geo *GeoPolicy, pools []Pool, src net.IP, ipv6 bool) string {
	if a.geo == nil || geo == nil || src == nil {
		return ""
	}
	cc, cont, ok := a.geo.lookup(src)
	if !ok {
		return ""
	}
	if geo != nil && len(geo.Named) > 0 {
		if pool := a.pickPoolByGeoFrom(geo, pools, cc, cont, ipv6); pool != "" {
			return pool
		}
		return ""
	}
	// Check in order: master -> standby -> fallback, but only if policy allows
	check := func(tier string, famV6 bool) bool {
		if !a.policyAllowsFor(geo, tier, cc, cont) {
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
	if a.policyAllowsFor(geo, "fallback", cc, cont) {
		return "fallback"
	}
	return ""
}

func geoPolicyAllows(tp GeoTierPolicy, country, continent string) bool {
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

func (a *authority) policyAllows(tier string, country, continent string) bool {
	return a.policyAllowsFor(a.zone.Geo, tier, country, continent)
}

func (a *authority) policyAllowsFor(g *GeoPolicy, tier string, country, continent string) bool {
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
	return geoPolicyAllows(tp, country, continent)
}

func (a *authority) pickPoolByGeo(country, continent string, ipv6 bool) string {
	return a.pickPoolByGeoFrom(a.zone.Geo, a.zone.Pools, country, continent, ipv6)
}

func (a *authority) pickPoolByGeoFrom(geo *GeoPolicy, pools []Pool, country, continent string, ipv6 bool) string {
	if geo == nil {
		return ""
	}
	for _, gp := range geo.Named {
		if !geoPolicyAllows(gp.Policy, country, continent) {
			continue
		}
		if rr := a.poolAnswersByNameFrom(pools, gp.Name, ipv6); rr != nil {
			return gp.Name
		}
	}
	return ""
}

func (a *authority) poolAnswersByName(name string, ipv6 bool) []dns.RR {
	return a.poolAnswersByNameFrom(a.zone.Pools, name, ipv6)
}

func (a *authority) poolAnswersByNameFrom(pools []Pool, name string, ipv6 bool) []dns.RR {
	return a.poolAnswersByNameWithState(pools, a.state, name, ipv6)
}

func (a *authority) poolAnswersByNameWithState(pools []Pool, st *state, name string, ipv6 bool) []dns.RR {
	for i := range pools {
		p := &pools[i]
		if !strings.EqualFold(strings.TrimSpace(p.Name), strings.TrimSpace(name)) {
			continue
		}
		if !a.poolMatches(p, ipv6, "public") || !a.poolUpWithState(st, p, ipv6) {
			return nil
		}
		return a.buildPoolAnswers(p, ipv6)
	}
	return nil
}

func (a *authority) privatePoolAnswers(ipv6 bool, src net.IP) []dns.RR {
	return a.privatePoolAnswersFrom(a.zone.Pools, ipv6, src)
}

func (a *authority) privatePoolAnswersFrom(pools []Pool, ipv6 bool, src net.IP) []dns.RR {
	return a.privatePoolAnswersWithState(pools, a.state, ipv6, src)
}

func (a *authority) privatePoolAnswersWithState(pools []Pool, st *state, ipv6 bool, src net.IP) []dns.RR {
	if src == nil {
		return nil
	}
	for rank := 0; rank <= 3; rank++ {
		for i := range pools {
			p := &pools[i]
			if poolRoleRank(p.Role) != rank || !a.poolMatches(p, ipv6, "private") || !a.poolClientAllowed(p, src) {
				continue
			}
			if !a.zone.PrivateAllowWhenIsolated && !a.poolUpWithState(st, p, ipv6) {
				continue
			}
			if rr := a.buildPoolAnswers(p, ipv6); rr != nil {
				return rr
			}
		}
	}
	return nil
}

func poolRoleRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "master", "primary":
		return 0
	case "standby", "secondary":
		return 1
	case "fallback":
		return 2
	default:
		return 3
	}
}

func (a *authority) publicPoolAnswers(ipv6 bool) []dns.RR {
	return a.publicPoolAnswersFrom(a.zone.Pools, ipv6)
}

func (a *authority) publicPoolAnswersFrom(pools []Pool, ipv6 bool) []dns.RR {
	return a.publicPoolAnswersWithState(pools, a.state, ipv6)
}

func (a *authority) publicPoolAnswersWithState(pools []Pool, st *state, ipv6 bool) []dns.RR {
	bestRank := 99
	for i := range pools {
		p := &pools[i]
		if !a.poolMatches(p, ipv6, "public") || !a.poolUpWithState(st, p, ipv6) {
			continue
		}
		rank := poolRoleRank(p.Role)
		if rank > bestRank {
			continue
		}
		if rr := a.buildPoolAnswers(p, ipv6); rr != nil {
			bestRank = rank
			return rr
		}
	}
	return nil
}

func hostOwnerName(apex, s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "", ".", "@":
		return ensureDot(apex)
	}
	if strings.Contains(s, ".") {
		return ensureDot(s)
	}
	apex = ensureDot(apex)
	return ensureDot(strings.TrimSuffix(s, ".") + "." + strings.TrimSuffix(apex, "."))
}

func (a *authority) serviceHost(owner string) *Host {
	owner = strings.ToLower(ensureDot(owner))
	for i := range a.zone.Hosts {
		h := &a.zone.Hosts[i]
		if strings.ToLower(hostOwnerName(a.zone.Name, h.Name)) == owner {
			return h
		}
	}
	return nil
}

func (a *authority) serviceState(owner string) *state {
	if a == nil {
		return nil
	}
	owner = strings.ToLower(ensureDot(owner))
	if st := a.hostStates[owner]; st != nil {
		return st
	}
	return a.state
}

func (a *authority) poolClientAllowed(p *Pool, src net.IP) bool {
	if p == nil || src == nil {
		return false
	}
	if len(p.ClientNets) == 0 {
		return strings.EqualFold(strings.TrimSpace(p.Class), "public")
	}
	for _, raw := range p.ClientNets {
		_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil && n.Contains(src) {
			return true
		}
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
	if len(a.zone.Pools) > 0 {
		a.probePoolRoles(ctx, a.state, a.zone.Pools, hc)
	} else {
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
	for i := range a.zone.Hosts {
		h := &a.zone.Hosts[i]
		if len(h.Pools) == 0 {
			continue
		}
		st := a.serviceState(hostOwnerName(a.zone.Name, h.Name))
		if st == nil || st == a.state {
			continue
		}
		hostHC := healthcheck.Effective(hostOwnerName(a.zone.Name, h.Name), mergeHealthConfig(a.zone.Health, h.Health))
		a.probePoolRoles(ctx, st, h.Pools, hostHC)
	}
}

func (a *authority) probePoolRoles(ctx context.Context, st *state, pools []Pool, hc config.HealthConfig) {
	m4 := healthcheck.ProbeAny(ctx, poolRoleIPsFrom(pools, "primary", false), hc)
	st.set("master", false, m4, a.cfg.Rise, a.cfg.Fall)
	m6 := healthcheck.ProbeAny(ctx, poolRoleIPsFrom(pools, "primary", true), hc)
	st.set("master", true, m6, a.cfg.Rise, a.cfg.Fall)
	s4 := healthcheck.ProbeAny(ctx, poolRoleIPsFrom(pools, "secondary", false), hc)
	st.set("standby", false, s4, a.cfg.Rise, a.cfg.Fall)
	s6 := healthcheck.ProbeAny(ctx, poolRoleIPsFrom(pools, "secondary", true), hc)
	st.set("standby", true, s6, a.cfg.Rise, a.cfg.Fall)
}

func mergeHealthConfig(base, override *config.HealthConfig) *config.HealthConfig {
	if base == nil && override == nil {
		return nil
	}
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}
	merged := *base
	if override.Kind != "" {
		merged.Kind = override.Kind
	}
	if override.HostHeader != "" {
		merged.HostHeader = override.HostHeader
	}
	if override.Path != "" {
		merged.Path = override.Path
	}
	if override.SNI != "" {
		merged.SNI = override.SNI
	}
	if override.InsecureTLS {
		merged.InsecureTLS = true
	}
	if override.Scheme != "" {
		merged.Scheme = override.Scheme
	}
	if override.Method != "" {
		merged.Method = override.Method
	}
	if override.Port != 0 {
		merged.Port = override.Port
	}
	if override.Expect != "" {
		merged.Expect = override.Expect
	}
	if override.TLSEnable {
		merged.TLSEnable = true
	}
	if override.ALPN != "" {
		merged.ALPN = override.ALPN
	}
	if len(override.ALPNProtos) > 0 {
		merged.ALPNProtos = append([]string(nil), override.ALPNProtos...)
	}
	if override.UDPPayloadB64 != "" {
		merged.UDPPayloadB64 = override.UDPPayloadB64
	}
	if override.UDPExpectRE != "" {
		merged.UDPExpectRE = override.UDPExpectRE
	}
	if override.ICMPPayloadB64 != "" {
		merged.ICMPPayloadB64 = override.ICMPPayloadB64
	}
	if override.Protocol != 0 {
		merged.Protocol = override.Protocol
	}
	return &merged
}

func poolRoleIPsFrom(pools []Pool, role string, ipv6 bool) []string {
	var ips []string
	for _, p := range pools {
		if !roleMatchesPool(role, p.Role) {
			continue
		}
		family := strings.ToLower(strings.TrimSpace(p.Family))
		if ipv6 && family != "ipv6" {
			continue
		}
		if !ipv6 && family != "ipv4" {
			continue
		}
		ips = append(ips, config.IPsFrom(p.Members)...)
	}
	return ips
}

func (a *authority) poolRoleIPs(role string, ipv6 bool) []string {
	var out []string
	for _, p := range a.zone.Pools {
		if !roleMatchesPool(role, p.Role) || !a.poolMatches(&p, ipv6, "") {
			continue
		}
		out = append(out, config.IPsFrom(p.Members)...)
	}
	return out
}
