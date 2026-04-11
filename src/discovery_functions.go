package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func bootstrapDiscoveredZones(cfg *Config) error {
	if cfg == nil || cfg.Discovery == nil {
		return nil
	}
	if len(cfg.Discovery.Masters) == 0 {
		return nil
	}
	names, err := fetchCatalogZoneNames(context.Background(), cfg)
	if err != nil {
		return err
	}
	existing := make(map[string]bool, len(cfg.Zones))
	for _, z := range cfg.Zones {
		existing[strings.ToLower(ensureDot(z.Name))] = true
	}
	for _, name := range names {
		if existing[strings.ToLower(name)] {
			continue
		}
		cfg.Zones = append(cfg.Zones, Zone{
			Name:      name,
			Serve:     "secondary",
			Masters:   append([]string(nil), cfg.Discovery.Masters...),
			XFRSource: cfg.Discovery.XFRSource,
			TSIG:      cloneTSIGZoneConfig(cfg.Discovery.TSIG),
		})
	}
	return nil
}

func appendCatalogZone(cfg *Config) {
	if cfg == nil || cfg.Discovery == nil || cfg.Discovery.CatalogZone == "" || len(cfg.Discovery.Masters) > 0 {
		return
	}
	catalogName := ensureDot(cfg.Discovery.CatalogZone)
	for _, z := range cfg.Zones {
		if strings.EqualFold(ensureDot(z.Name), catalogName) {
			return
		}
	}
	ns := firstCatalogNS(cfg, catalogName)
	admin := firstCatalogAdmin(cfg, catalogName)
	ttl := cfg.Discovery.TTL
	if ttl == 0 {
		ttl = 60
	}
	records := make([]TXTRecord, 0, len(cfg.Zones))
	sorted := make([]string, 0, len(cfg.Zones))
	for _, z := range cfg.Zones {
		name := ensureDot(z.Name)
		if strings.EqualFold(name, catalogName) {
			continue
		}
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for i, name := range sorted {
		records = append(records, TXTRecord{
			Name: fmt.Sprintf("zone-%d", i+1),
			Text: []string{"zone=" + name},
			TTL:  ttl,
		})
	}
	cfg.Zones = append(cfg.Zones, Zone{
		Name:      catalogName,
		NS:        []string{ns},
		Admin:     admin,
		TTLSOA:    ttl,
		TTLAnswer: ttl,
		Refresh:   60,
		Retry:     10,
		Expire:    90,
		Minttl:    ttl,
		Serve:     "primary",
		TXT:       records,
		TSIG:      cloneTSIGZoneConfig(cfg.Discovery.TSIG),
	})
}

func firstCatalogNS(cfg *Config, fallbackZone string) string {
	for _, z := range cfg.Zones {
		if len(z.NS) > 0 {
			return ensureDot(z.NS[0])
		}
	}
	return "ns." + ensureDot(fallbackZone)
}

func firstCatalogAdmin(cfg *Config, fallbackZone string) string {
	for _, z := range cfg.Zones {
		if z.Admin != "" {
			return ensureDot(z.Admin)
		}
	}
	return "hostmaster." + ensureDot(fallbackZone)
}

func fetchCatalogZoneNames(ctx context.Context, cfg *Config) ([]string, error) {
	if cfg == nil || cfg.Discovery == nil {
		return nil, nil
	}
	records, err := transferAXFR(ctx, ensureDot(cfg.Discovery.CatalogZone), cfg.Discovery.Masters, cfg.Discovery.XFRSource, cfg.Discovery.TSIG, time.Duration(cfg.TimeoutSec)*time.Second)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, rr := range records {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		for _, s := range txt.Txt {
			if !strings.HasPrefix(strings.ToLower(s), "zone=") {
				continue
			}
			name := ensureDot(strings.TrimSpace(s[len("zone="):]))
			if name == "." || strings.EqualFold(name, ensureDot(cfg.Discovery.CatalogZone)) || seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func transferAXFR(ctx context.Context, zoneName string, masters []string, xfrSource string, tsig *TSIGZoneConfig, timeout time.Duration) ([]dns.RR, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	var lastErr error
	for _, master := range masters {
		addr := master
		if !strings.Contains(addr, ":") || strings.HasSuffix(addr, "]") {
			addr = net.JoinHostPort(addr, "53")
		}
		m := new(dns.Msg)
		m.SetAxfr(zoneName)
		var tr *dns.Transfer
		if xfrSource != "" {
			srcIP := net.ParseIP(strings.TrimSpace(xfrSource))
			if srcIP == nil {
				lastErr = fmt.Errorf("invalid xfr_source %q", xfrSource)
				continue
			}
			dialer := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: srcIP}}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				lastErr = err
				continue
			}
			tr = &dns.Transfer{Conn: &dns.Conn{Conn: conn}}
		}
		if cfg := preferredTSIGConfig(tsig, nil); cfg != nil && len(cfg.Keys) > 0 {
			key := cfg.Keys[0]
			name := ensureDot(key.Name)
			alg := normalizeTSIGAlgorithm(key.Algorithm)
			if alg == "" {
				alg = dns.HmacSHA256
			}
			if tr == nil {
				tr = &dns.Transfer{}
			}
			tr.TsigSecret = map[string]string{name: key.Secret}
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
		return all[1 : len(all)-1], nil
	}
	return nil, lastErr
}

func cloneTSIGZoneConfig(cfg *TSIGZoneConfig) *TSIGZoneConfig {
	if cfg == nil {
		return nil
	}
	out := *cfg
	if len(cfg.Keys) > 0 {
		out.Keys = make([]TSIGKey, len(cfg.Keys))
		copy(out.Keys, cfg.Keys)
	}
	return &out
}

func preferredTSIGConfig(primary, fallback *TSIGZoneConfig) *TSIGZoneConfig {
	if primary != nil && len(primary.Keys) > 0 {
		return primary
	}
	if fallback != nil && len(fallback.Keys) > 0 {
		return fallback
	}
	return nil
}
