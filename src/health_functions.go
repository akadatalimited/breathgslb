package main

import (
	"context"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/akadatalimited/breathgslb/src/healthcheck"
)

// Health check functions

// snapshot returns the current up/down state for all address families.
func (s *state) snapshot() (mV4, mV6, sV4, sV6 bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.master.v4.up, s.master.v6.up, s.standby.v4.up, s.standby.v6.up
}

// set updates the up/down state for a specific tier and address family.
// It implements flap damping with rise/fall counters and cooldown periods.
func (s *state) set(tier string, ipv6 bool, obsUp bool, riseTarget, fallTarget int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f *famState
	if tier == "master" {
		if ipv6 {
			f = &s.master.v6
		} else {
			f = &s.master.v4
		}
	} else { // standby
		if ipv6 {
			f = &s.standby.v6
		} else {
			f = &s.standby.v4
		}
	}
	if obsUp {
		f.rise++
		f.fall = 0
	} else {
		f.fall++
		f.rise = 0
	}
	proposed := f.up
	if f.rise >= riseTarget {
		proposed = true
	}
	if f.fall >= fallTarget {
		proposed = false
	}
	if proposed != f.up && time.Since(f.lastChange) >= s.cooldown {
		f.up = proposed
		f.lastChange = time.Now()
	}
}

// healthLoop runs periodic health checks for an authority.
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

// checkOnce performs a single round of health checks for all endpoints.
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

// aliasLookup resolves a hostname to a list of IP addresses.
func aliasLookup(ctx context.Context, target string) []net.IP {
	target = strings.TrimSuffix(target, ".")
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return nil
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips
}