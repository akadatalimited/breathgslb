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

// GenerateReverseZones writes reverse PTR zones for marked addresses.
func GenerateReverseZones(cfg *Config) error {
	if cfg.ReverseDir == "" {
		return nil
	}
	if err := os.MkdirAll(cfg.ReverseDir, 0o755); err != nil {
		return err
	}
	for _, z := range cfg.Zones {
		var records []map[string]string
		add := func(list []IPAddr) {
			for _, a := range list {
				if !a.Reverse {
					continue
				}
				ip := net.ParseIP(a.IP)
				if ip == nil {
					continue
				}
				rev := reverseName(ip)
				if rev == "" {
					continue
				}
				records = append(records, map[string]string{"name": rev, "ptr": EnsureDot(z.Name)})
			}
		}
		add(z.AMaster)
		add(z.AAAAMaster)
		add(z.AStandby)
		add(z.AAAAStandby)
		add(z.AFallback)
		add(z.AAAAFallback)
		add(z.AMasterPrivate)
		add(z.AAAAMasterPrivate)
		add(z.AStandbyPrivate)
		add(z.AAAAStandbyPrivate)
		add(z.AFallbackPrivate)
		add(z.AAAAFallbackPrivate)
		if len(records) == 0 {
			continue
		}
		data, err := yaml.Marshal(map[string]any{"records": records})
		if err != nil {
			return err
		}
		fname := filepath.Join(cfg.ReverseDir, strings.TrimSuffix(z.Name, ".")+".yaml")
		if err := os.WriteFile(fname, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
