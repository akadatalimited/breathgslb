package main

import (
	"bufio"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type liveConfig struct {
	Zone       string
	TSIGName   string
	TSIGSecret string
	Primary    []string
	Secondary  []string
	Standby    []string
}

func loadLiveConfig(t *testing.T) *liveConfig {
	data, err := os.ReadFile("tests.config")
	if err != nil {
		t.Skip("tests.config missing")
	}
	cfg := &liveConfig{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		parseAddrs := func(v string) []string {
			fields := strings.Split(v, ",")
			var res []string
			for _, f := range fields {
				if a := strings.TrimSpace(f); a != "" {
					res = append(res, ensurePort(a))
				}
			}
			return res
		}
		switch key {
		case "zone":
			cfg.Zone = val
		case "tsig_name":
			cfg.TSIGName = val
		case "tsig_secret":
			cfg.TSIGSecret = val
		case "primary":
			cfg.Primary = parseAddrs(val)
		case "secondary":
			cfg.Secondary = parseAddrs(val)
		case "standby":
			cfg.Standby = parseAddrs(val)
		}
	}
	if cfg.Zone == "" || cfg.TSIGName == "" || cfg.TSIGSecret == "" || len(cfg.Primary) == 0 {
		t.Skip("tests.config incomplete")
	}
	return cfg
}

func ensurePort(addr string) string {
	if strings.Contains(addr, ":") && !strings.Contains(addr, "]") {
		return "[" + addr + "]:53"
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "53")
	}
	return addr
}

func axfr(t *testing.T, addr string, cfg *liveConfig) []dns.RR {
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{cfg.TSIGName: cfg.TSIGSecret}
	m := new(dns.Msg)
	m.SetAxfr(cfg.Zone)
	m.SetTsig(cfg.TSIGName, dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("axfr %s: %v", addr, err)
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("axfr env %s: %v", addr, e.Error)
		}
		rrs = append(rrs, e.RR...)
	}
	return rrs
}

func ixfr(t *testing.T, addr string, cfg *liveConfig) {
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{cfg.TSIGName: cfg.TSIGSecret}
	m := new(dns.Msg)
	m.SetIxfr(cfg.Zone, 0, "", "")
	m.SetTsig(cfg.TSIGName, dns.HmacSHA256, 300, time.Now().Unix())
	env, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("ixfr %s: %v", addr, err)
	}
	for e := range env {
		if e.Error != nil {
			t.Fatalf("ixfr env %s: %v", addr, e.Error)
		}
	}
}

func equalRR(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}

func TestIntegrationAXFRChain(t *testing.T) {
	cfg := loadLiveConfig(t)
	primary := axfr(t, cfg.Primary[0], cfg)
	if len(cfg.Secondary) == 0 || len(cfg.Standby) == 0 {
		t.Skip("need secondary and standby for chain test")
	}
	secondary := axfr(t, cfg.Secondary[0], cfg)
	if !equalRR(primary, secondary) {
		t.Fatalf("secondary does not match primary")
	}
	standby := axfr(t, cfg.Standby[0], cfg)
	if !equalRR(secondary, standby) {
		t.Fatalf("standby does not match secondary")
	}
}

func TestIntegrationIXFR(t *testing.T) {
	cfg := loadLiveConfig(t)
	addrs := append(append(cfg.Primary, cfg.Secondary...), cfg.Standby...)
	for _, addr := range addrs {
		ixfr(t, addr, cfg)
	}
}
