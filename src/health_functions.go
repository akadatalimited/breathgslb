package main

import (
	"context"
	"net"
	"strings"
	"time"
)

// Health check functions

// snapshot returns the current up/down state for all address families.
func (s *state) snapshot() (mV4, mV6, sV4, sV6 bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.master.v4.up, s.master.v6.up, s.standby.v4.up, s.standby.v6.up
}

func tierUpState(s *state, tier string, ipv6 bool) bool {
	if s == nil {
		return false
	}
	mV4, mV6, sV4, sV6 := s.snapshot()
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
		return true
	}
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
