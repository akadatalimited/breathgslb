package main

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type liveConfig struct {
	Zone       string `yaml:"zone"`
	TSIGName   string `yaml:"tsig_name"`
	TSIGSecret string `yaml:"tsig_secret"`
	Primary    string `yaml:"primary"`
	Secondary  string `yaml:"secondary"`
	Standby    string `yaml:"standby"`
	Tester     string `yaml:"tester"`
}

func loadLiveConfig(t *testing.T) *liveConfig {
	data, err := os.ReadFile("tests.config")
	if err != nil {
		t.Skip("tests.config missing")
	}
	cfg := &liveConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		t.Fatalf("parse tests.config: %v", err)
	}
	if cfg.Zone == "" || cfg.TSIGName == "" || cfg.TSIGSecret == "" || cfg.Primary == "" {
		t.Skip("tests.config incomplete")
	}
	cfg.Primary = ensurePort(cfg.Primary)
	if cfg.Secondary != "" {
		cfg.Secondary = ensurePort(cfg.Secondary)
	}
	if cfg.Standby != "" {
		cfg.Standby = ensurePort(cfg.Standby)
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
	if cfg.Secondary == "" || cfg.Standby == "" {
		t.Skip("need secondary and standby for chain test")
	}
	primary := axfr(t, cfg.Primary, cfg)
	secondary := axfr(t, cfg.Secondary, cfg)
	if !equalRR(primary, secondary) {
		t.Fatalf("secondary does not match primary")
	}
	standby := axfr(t, cfg.Standby, cfg)
	if !equalRR(secondary, standby) {
		t.Fatalf("standby does not match secondary")
	}
}

func TestIntegrationIXFR(t *testing.T) {
	cfg := loadLiveConfig(t)
	addrs := []string{cfg.Primary}
	if cfg.Secondary != "" {
		addrs = append(addrs, cfg.Secondary)
	}
	if cfg.Standby != "" {
		addrs = append(addrs, cfg.Standby)
	}
	for _, addr := range addrs {
		ixfr(t, addr, cfg)
	}
}
