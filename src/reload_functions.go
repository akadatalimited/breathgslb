package main

import (
	"context"
	"log"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const minReloadInterval = 2 * time.Second

func (r *router) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if r == nil {
		dns.HandleFailed(w, req)
		return
	}
	h, _ := r.inner.Load().(dns.Handler)
	if h == nil {
		dns.HandleFailed(w, req)
		return
	}
	h.ServeDNS(w, req)
}

func loadRuntimeConfig(cfgPath string) (*Config, string, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, "", err
	}
	config.SetupDefaults(cfg)
	config.GenerateTSIGKeys(cfg)
	if err := bootstrapDiscoveredZones(cfg); err != nil {
		return nil, "", err
	}
	appendCatalogZone(cfg)
	sig, err := runtimeConfigSignature(cfg)
	if err != nil {
		return nil, "", err
	}
	return cfg, sig, nil
}

func runtimeConfigSignature(cfg *Config) (string, error) {
	if cfg == nil {
		return "", nil
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func reloadRuntime(cfgPath string) error {
	cfg, sig, err := loadRuntimeConfig(cfgPath)
	if err != nil {
		return err
	}

	current.mu.Lock()
	if sig == current.cfgSig {
		current.mu.Unlock()
		return nil
	}
	prevAuths := current.auths
	oldGeo := current.geo
	rt := current.rt
	current.mu.Unlock()

	geo := newGeoResolver(cfg.GeoIP)
	mux, auths := buildMux(cfg, geo, sup, prevAuths)

	current.mu.Lock()
	current.cfg = cfg
	current.cfgSig = sig
	current.auths = auths
	current.geo = geo
	if rt != nil {
		rt.inner.Store(mux)
	}
	current.mu.Unlock()

	for _, auth := range prevAuths {
		if auth != nil && auth.cancel != nil {
			auth.cancel()
		}
	}
	if oldGeo != nil {
		oldGeo.Close()
	}
	log.Printf("reloaded runtime configuration")
	return nil
}

func autoReloadLoop(ctx context.Context, cfgPath string) {
	for {
		current.mu.Lock()
		interval := time.Duration(0)
		if current.cfg != nil && current.cfg.IntervalSec > 0 {
			interval = time.Duration(current.cfg.IntervalSec) * time.Second
		}
		current.mu.Unlock()
		if interval < minReloadInterval {
			interval = minReloadInterval
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := reloadRuntime(cfgPath); err != nil {
			log.Printf("runtime reload failed: %v", err)
		}
	}
}
