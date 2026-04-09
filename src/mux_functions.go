package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// buildMux constructs the DNS handler mux and initializes authorities for all zones.
func buildMux(cfg *Config, gr *geoResolver, sup *supervisor, prev map[string]*authority) (dns.Handler, map[string]*authority) {
	mux := dns.NewServeMux()
	auths := make(map[string]*authority)
	lightup := compileLightupSpecs(cfg.Zones)
	for _, z := range cfg.Zones {
		zname := ensureDot(z.Name)
		ctx, cancel := context.WithCancel(context.Background())
		st := &state{cooldown: time.Duration(cfg.CooldownSec) * time.Second}
		auth := &authority{cfg: cfg, zone: z, state: st, ctx: ctx, cancel: cancel, geo: gr, lightup: lightup, sigCache: make(map[string]sigCacheEntry)}
		if strings.ToLower(z.Serve) == "secondary" {
			auth.serial = 0
			auth.zidx = nil
		} else {
			auth.serial = nextSerial(zname)
			auth.zidx = buildIndex(z)
		}
		// DNSSEC keys & index
		auth.keys = loadDNSSEC(z)
		// parse local CIDRs once
		auth.cidrInit()

		if prev != nil {
			if old := prev[zname]; old != nil {
				del, add := rrDiff(old.axfrRecords(), auth.axfrRecords())
				if len(del) > 0 || len(add) > 0 {
					auth.ixfr = &ixfrDelta{old: old.soa().(*dns.SOA), del: del, new: auth.soa().(*dns.SOA), add: add}
				}
			}
		}

		mux.HandleFunc(zname, auth.handle)
		auths[zname] = auth
		if strings.ToLower(z.Serve) == "secondary" && len(z.Masters) > 0 {
			if sup != nil {
				sup.watch(ctx, zname+" fetchLoop", auth.fetchLoop)
			} else {
				go auth.fetchLoop()
			}
			log.Printf("serving secondary zone %s", zname)
		} else {
			if sup != nil {
				sup.watch(ctx, zname+" healthLoop", auth.healthLoop)
				sup.watch(ctx, zname+" purgeLoop", auth.purgeLoop)
			} else {
				go auth.healthLoop()
				go auth.purgeLoop()
			}
			log.Printf("serving zone %s", zname)
		}
	}
	return mux, auths
}
