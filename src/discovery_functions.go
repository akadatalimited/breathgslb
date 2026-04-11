package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func bootstrapDiscoveredZones(cfg *Config) error {
	if cfg == nil || cfg.Discovery == nil {
		return nil
	}
	if len(cfg.Discovery.Masters) == 0 {
		return nil
	}
	zones, err := fetchCatalogZones(context.Background(), cfg)
	if err != nil {
		return err
	}
	existing := make(map[string]bool, len(cfg.Zones))
	for _, z := range cfg.Zones {
		existing[strings.ToLower(ensureDot(z.Name))] = true
	}
	for _, discovered := range zones {
		name := ensureDot(discovered.Name)
		if existing[strings.ToLower(name)] {
			continue
		}
		discovered.Name = name
		discovered.Serve = "secondary"
		discovered.Masters = append([]string(nil), cfg.Discovery.Masters...)
		discovered.XFRSource = cfg.Discovery.XFRSource
		discovered.TSIG = mergeDiscoveredTSIG(discovered.TSIG, cfg.Discovery.TSIG)
		cfg.Zones = append(cfg.Zones, discovered)
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
		text := []string{"zone=" + name}
		for _, z := range cfg.Zones {
			if !strings.EqualFold(ensureDot(z.Name), name) {
				continue
			}
			payload, err := catalogZonePayload(z)
			if err == nil && payload != "" {
				text = append(text, chunkTXT("cfg64=", payload)...)
			}
			break
		}
		records = append(records, TXTRecord{Name: fmt.Sprintf("zone-%d", i+1), Text: text, TTL: ttl})
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

func fetchCatalogZones(ctx context.Context, cfg *Config) ([]Zone, error) {
	if cfg == nil || cfg.Discovery == nil {
		return nil, nil
	}
	records, err := transferAXFR(ctx, ensureDot(cfg.Discovery.CatalogZone), cfg.Discovery.Masters, cfg.Discovery.XFRSource, cfg.Discovery.TSIG, time.Duration(cfg.TimeoutSec)*time.Second)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var zones []Zone
	for _, rr := range records {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		var (
			name   string
			cfg64s []string
		)
		for _, s := range txt.Txt {
			switch {
			case strings.HasPrefix(strings.ToLower(s), "zone="):
				name = ensureDot(strings.TrimSpace(s[len("zone="):]))
			case strings.HasPrefix(strings.ToLower(s), "cfg64="):
				cfg64s = append(cfg64s, strings.TrimSpace(s[len("cfg64="):]))
			}
		}
		if name == "." || strings.EqualFold(name, ensureDot(cfg.Discovery.CatalogZone)) || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		z := Zone{Name: name}
		if len(cfg64s) > 0 {
			if decoded, err := decodeCatalogZone(strings.Join(cfg64s, "")); err == nil {
				z = decoded
				z.Name = ensureDot(z.Name)
			}
		}
		if z.Name == "" {
			z.Name = name
		}
		zones = append(zones, z)
	}
	sort.Slice(zones, func(i, j int) bool {
		return strings.ToLower(ensureDot(zones[i].Name)) < strings.ToLower(ensureDot(zones[j].Name))
	})
	return zones, nil
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
	if primary != nil && tsigConfigUsable(primary) {
		return primary
	}
	if fallback != nil && tsigConfigUsable(fallback) {
		return fallback
	}
	return nil
}

func tsigConfigUsable(cfg *TSIGZoneConfig) bool {
	if cfg == nil {
		return false
	}
	for _, k := range cfg.Keys {
		if strings.TrimSpace(k.Name) != "" && strings.TrimSpace(k.Secret) != "" {
			return true
		}
	}
	return false
}

func mergeDiscoveredTSIG(zoneTSIG, discoveryTSIG *TSIGZoneConfig) *TSIGZoneConfig {
	if zoneTSIG == nil || len(zoneTSIG.Keys) == 0 {
		return cloneTSIGZoneConfig(discoveryTSIG)
	}
	out := cloneTSIGZoneConfig(zoneTSIG)
	if discoveryTSIG == nil {
		return out
	}
	byName := make(map[string]TSIGKey, len(discoveryTSIG.Keys))
	for _, k := range discoveryTSIG.Keys {
		byName[strings.ToLower(ensureDot(k.Name))] = k
	}
	for i := range out.Keys {
		name := strings.ToLower(ensureDot(out.Keys[i].Name))
		dk, ok := byName[name]
		if !ok {
			continue
		}
		if strings.TrimSpace(out.Keys[i].Secret) == "" {
			out.Keys[i].Secret = dk.Secret
		}
		if strings.TrimSpace(out.Keys[i].Algorithm) == "" {
			out.Keys[i].Algorithm = dk.Algorithm
		}
		if len(out.Keys[i].AllowXFRFrom) == 0 {
			out.Keys[i].AllowXFRFrom = append([]string(nil), dk.AllowXFRFrom...)
		}
	}
	if !tsigConfigUsable(out) {
		return cloneTSIGZoneConfig(discoveryTSIG)
	}
	return out
}

func catalogZonePayload(z Zone) (string, error) {
	exported := catalogExportZone(z)
	b, err := yaml.Marshal(&exported)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func decodeCatalogZone(payload string) (Zone, error) {
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return Zone{}, err
	}
	var z Zone
	if err := yaml.Unmarshal(b, &z); err != nil {
		return Zone{}, err
	}
	return z, nil
}

func catalogExportZone(z Zone) Zone {
	out := z
	out.Serve = ""
	out.Masters = nil
	out.XFRSource = ""
	if out.TSIG != nil {
		cp := *out.TSIG
		if len(cp.Keys) > 0 {
			cp.Keys = append([]TSIGKey(nil), cp.Keys...)
			for i := range cp.Keys {
				cp.Keys[i].Secret = ""
				cp.Keys[i].AllowXFRFrom = nil
			}
		}
		cp.AllowUnsigned = false
		cp.SeedEnv = ""
		out.TSIG = &cp
	}
	return out
}

func chunkTXT(prefix, value string) []string {
	if value == "" {
		return nil
	}
	maxChunk := 255 - len(prefix)
	if maxChunk <= 0 {
		return []string{prefix}
	}
	var out []string
	for len(value) > 0 {
		n := maxChunk
		if n > len(value) {
			n = len(value)
		}
		out = append(out, prefix+value[:n])
		value = value[n:]
	}
	return out
}
