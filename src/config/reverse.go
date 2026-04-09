package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// reverseName converts an IP to its reverse DNS owner name.
func reverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	hex := make([]byte, 32)
	for i, b := range v6 {
		hex[i*2] = "0123456789abcdef"[b>>4]
		hex[i*2+1] = "0123456789abcdef"[b&0x0f]
	}
	var parts []string
	for i := len(hex) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[i]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa."
}

// GenerateReverseZones promotes reverse PTR data into live zones and, when
// requested, writes any auto-generated fallback zones to disk for inspection.
func GenerateReverseZones(cfg *Config) error {
	generated, err := appendReverseZones(cfg)
	if err != nil {
		return err
	}
	if cfg.ReverseDir == "" || len(generated) == 0 {
		return nil
	}
	if err := os.MkdirAll(cfg.ReverseDir, 0o755); err != nil {
		return err
	}
	for _, z := range generated {
		data, err := yaml.Marshal([]Zone{z})
		if err != nil {
			return err
		}
		fname := filepath.Join(cfg.ReverseDir, strings.TrimSuffix(z.Name, ".")+".rev.yaml")
		if err := os.WriteFile(fname, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func appendReverseZones(cfg *Config) ([]Zone, error) {
	baseZones := len(cfg.Zones)
	generated := map[string]*Zone{}
	order := []string{}

	for i := 0; i < baseZones; i++ {
		src := cfg.Zones[i]
		add := func(list []IPAddr) error {
			for _, a := range list {
				if !a.Reverse {
					continue
				}
				ip := net.ParseIP(a.IP)
				if ip == nil {
					continue
				}
				owner := reverseName(ip)
				if owner == "" {
					continue
				}
				target := EnsureDot(src.Name)
				targetZone := findBestReverseZone(cfg.Zones[:baseZones], owner)
				if targetZone != nil {
					addPTRToZone(targetZone, owner, target)
					continue
				}
				z, ok := generated[owner]
				if !ok {
					newZone := Zone{
						Name:      owner,
						NS:        append([]string(nil), src.NS...),
						Admin:     src.Admin,
						TTLSOA:    src.TTLSOA,
						TTLAnswer: src.TTLAnswer,
						Refresh:   src.Refresh,
						Retry:     src.Retry,
						Expire:    src.Expire,
						Minttl:    src.Minttl,
						DNSSEC:    cloneDNSSEC(src.DNSSEC),
						TSIG:      cloneTSIG(src.TSIG),
					}
					generated[owner] = &newZone
					order = append(order, owner)
					z = &newZone
					generated[owner] = z
				}
				addPTRToZone(z, owner, target)
			}
			return nil
		}
		if err := add(src.AMaster); err != nil {
			return nil, err
		}
		if err := add(src.AAAAMaster); err != nil {
			return nil, err
		}
		if err := add(src.AStandby); err != nil {
			return nil, err
		}
		if err := add(src.AAAAStandby); err != nil {
			return nil, err
		}
		if err := add(src.AFallback); err != nil {
			return nil, err
		}
		if err := add(src.AAAAFallback); err != nil {
			return nil, err
		}
		if err := add(src.AMasterPrivate); err != nil {
			return nil, err
		}
		if err := add(src.AAAAMasterPrivate); err != nil {
			return nil, err
		}
		if err := add(src.AStandbyPrivate); err != nil {
			return nil, err
		}
		if err := add(src.AAAAStandbyPrivate); err != nil {
			return nil, err
		}
		if err := add(src.AFallbackPrivate); err != nil {
			return nil, err
		}
		if err := add(src.AAAAFallbackPrivate); err != nil {
			return nil, err
		}
	}

	out := make([]Zone, 0, len(order))
	for _, name := range order {
		out = append(out, *generated[name])
		cfg.Zones = append(cfg.Zones, *generated[name])
	}
	return out, nil
}

func findBestReverseZone(zones []Zone, owner string) *Zone {
	var best *Zone
	bestLen := -1
	owner = strings.ToLower(EnsureDot(owner))
	for i := range zones {
		name := strings.ToLower(EnsureDot(zones[i].Name))
		if !isReverseZoneName(name) {
			continue
		}
		if owner != name && !strings.HasSuffix(owner, "."+strings.TrimSuffix(name, ".")) && !strings.HasSuffix(owner, name) {
			continue
		}
		if len(name) > bestLen {
			best = &zones[i]
			bestLen = len(name)
		}
	}
	return best
}

func isReverseZoneName(name string) bool {
	name = strings.ToLower(EnsureDot(name))
	return strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.")
}

func addPTRToZone(z *Zone, owner, target string) {
	owner = EnsureDot(owner)
	target = EnsureDot(target)
	for _, p := range z.PTR {
		if ptrOwnerName(z.Name, p.Name) == owner {
			return
		}
	}
	name := owner
	if owner == EnsureDot(z.Name) {
		name = "@"
	}
	z.PTR = append(z.PTR, PTRRecord{Name: name, PTR: target})
}

func ptrOwnerName(apex, s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == "@" {
		return EnsureDot(apex)
	}
	return EnsureDot(s)
}

func cloneDNSSEC(d *DNSSECZoneConfig) *DNSSECZoneConfig {
	if d == nil {
		return nil
	}
	cp := *d
	return &cp
}

func cloneTSIG(t *TSIGZoneConfig) *TSIGZoneConfig {
	if t == nil {
		return nil
	}
	cp := *t
	if len(t.Keys) > 0 {
		cp.Keys = append([]TSIGKey(nil), t.Keys...)
	}
	return &cp
}
