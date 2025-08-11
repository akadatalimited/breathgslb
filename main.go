// breathgslb/main.go
// A tiny authoritative DNS server for one or a few delegated zones.
// Chooses A/AAAA answers based on active health checks with flap damping.
//
// Dependencies: go 1.21+, module github.com/miekg/dns
// Build: `go build -o breathgslb`
//
// Example run:
//   ./breathgslb -config config.yaml
//
// Parent zone must delegate e.g. `articles.akadata.ltd.` to this server's NS.
// Provide glue A/AAAA for that NS in the parent.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/miekg/dns"
)

type Config struct {
	Listen        string   `yaml:"listen"`            // ":53" or "0.0.0.0:5353"
	Zones         []Zone   `yaml:"zones"`
	TimeoutSec    int      `yaml:"timeout_sec"`       // HTTP timeout per check
	IntervalSec   int      `yaml:"interval_sec"`      // how often to run checks
	Rise          int      `yaml:"rise"`              // consecutive successes to mark UP
	Fall          int      `yaml:"fall"`              // consecutive failures to mark DOWN
	EDNSBuf       int      `yaml:"edns_buf"`          // e.g., 1232 or 4096
	LogQueries    bool     `yaml:"log_queries"`
}

type Zone struct {
	Name      string   `yaml:"name"`       // e.g., "articles.akadata.ltd."
	NS        []string `yaml:"ns"`         // authoritative NS names (FQDNs, trailing dot)
	Admin     string   `yaml:"admin"`      // hostmaster email as hostmaster.example.com.
	TTLSOA    uint32   `yaml:"ttl_soa"`
	TTLAnswer uint32   `yaml:"ttl_answer"`
	// Healthy endpoints to serve when checks pass. May include one or many.
	AHealthy   []string `yaml:"a_healthy"`   // IPv4 literals
	AAAAHealthy []string `yaml:"aaaa_healthy"` // IPv6 literals
	// Fallback endpoints served when unhealthy or flapping.
	AFallback    []string `yaml:"a_fallback"`
	AAAAFallback []string `yaml:"aaaa_fallback"`
	// Health checks performed directly by IP to avoid DNS recursion on the same name.
	// If both v4 and v6 are configured, each is checked independently.
	Health struct {
		HostHeader string   `yaml:"host_header"` // e.g., "articles.akadata.ltd"
		Path       string   `yaml:"path"`        // e.g., "/health"
		// Optional TLS settings
		SNI        string   `yaml:"sni"`         // usually same as HostHeader
		InsecureTLS bool    `yaml:"insecure_tls"` // allow self-signed while bootstrapping
	} `yaml:"health"`
}

type state struct {
	mu sync.RWMutex
	// current health status
	v4Up bool
	v6Up bool
	// flapping counters
	v4Rise int
	v4Fall int
	v6Rise int
	v6Fall int
}

func (s *state) setV4(up bool, riseTarget, fallTarget int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up {
		s.v4Rise++
		s.v4Fall = 0
		if s.v4Rise >= riseTarget {
			s.v4Up = true
		}
	} else {
		s.v4Fall++
		s.v4Rise = 0
		if s.v4Fall >= fallTarget {
			s.v4Up = false
		}
	}
}

func (s *state) setV6(up bool, riseTarget, fallTarget int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up {
		s.v6Rise++
		s.v6Fall = 0
		if s.v6Rise >= riseTarget {
			s.v6Up = true
		}
	} else {
		s.v6Fall++
		s.v6Rise = 0
		if s.v6Fall >= fallTarget {
			s.v6Up = false
		}
	}
}

func (s *state) snapshot() (v4, v6 bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v4Up, s.v6Up
}

type authority struct {
	cfg   Config
	zone  Zone
	state *state
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "config.yaml", "path to YAML config")
	flag.Parse()

	cfgData, err := os.ReadFile(cfgPath)
	if err != nil { log.Fatalf("read config: %v", err) }
	var cfg Config
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil { log.Fatalf("parse config: %v", err) }
	if cfg.Listen == "" { cfg.Listen = ":53" }
	if cfg.TimeoutSec == 0 { cfg.TimeoutSec = 4 }
	if cfg.IntervalSec == 0 { cfg.IntervalSec = 5 }
	if cfg.Rise == 0 { cfg.Rise = 2 }
	if cfg.Fall == 0 { cfg.Fall = 2 }
	if cfg.EDNSBuf == 0 { cfg.EDNSBuf = 1232 }

	mux := dns.NewServeMux()

	for _, z := range cfg.Zones {
		zname := ensureDot(z.Name)
		st := &state{}
		auth := &authority{cfg: cfg, zone: z, state: st}
		mux.HandleFunc(zname, auth.handle)
		go auth.healthLoop()
		log.Printf("serving zone %s", zname)
	}

	server := &dns.Server{Addr: cfg.Listen, Net: "udp", Handler: dnsutil{cfg: cfg, inner: mux}}
	serverTCP := &dns.Server{Addr: cfg.Listen, Net: "tcp", Handler: dnsutil{cfg: cfg, inner: mux}}
	// Start UDP
	go func() {
		if err := server.ListenAndServe(); err != nil { log.Fatalf("udp: %v", err) }
	}()
	// Start TCP
	if err := serverTCP.ListenAndServe(); err != nil { log.Fatalf("tcp: %v", err) }
}

type dnsutil struct{ cfg Config; inner dns.Handler }

func (d dnsutil) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if o := r.IsEdns0(); o != nil { o.SetUDPSize(uint16(d.cfg.EDNSBuf)) }
	d.inner.ServeDNS(w, r)
}

func (a *authority) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := ensureDot(q.Name)
	z := ensureDot(a.zone.Name)

	if a.cfg.LogQueries {
		log.Printf("q: %s %s", name, dns.TypeToString[q.Qtype])
	}

	// Serve SOA/NS for zone apex
	if name == z {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, a.soa())
		case dns.TypeNS:
			for _, ns := range a.zone.NS { m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)}) }
		case dns.TypeA, dns.TypeAAAA:
			// fall through to address answers below
		}
	}

	switch q.Qtype {
	case dns.TypeA:
		for _, rr := range a.addrA() { m.Answer = append(m.Answer, rr) }
	case dns.TypeAAAA:
		for _, rr := range a.addrAAAA() { m.Answer = append(m.Answer, rr) }
	case dns.TypeSOA, dns.TypeNS:
		// already handled above
	default:
		// Minimal: NXDOMAIN for unsupported types
		m.Rcode = dns.RcodeNameError
	}

	// Add authority NS + SOA in authority section for negative answers
	if len(m.Answer) == 0 {
		for _, ns := range a.zone.NS { m.Ns = append(m.Ns, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)}) }
		m.Ns = append(m.Ns, a.soa())
	}

	_ = w.WriteMsg(m)
}

func (a *authority) soa() dns.RR {
	z := ensureDot(a.zone.Name)
	nsPrimary := ensureDot(a.zone.NS[0])
	return &dns.SOA{Hdr: hdr(z, dns.TypeSOA, a.zone.TTLSOA), Ns: nsPrimary, Mbox: ensureDot(a.zone.Admin), Serial: uint32(time.Now().Unix()), Refresh: 60, Retry: 30, Expire: 600, Minttl: a.zone.TTLSOA}
}

func hdr(name string, t uint16, ttl uint32) dns.RR_Header { return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl} }

func ensureDot(s string) string {
	if !strings.HasSuffix(s, ".") { return s + "." }
	return s
}

func (a *authority) addrA() []dns.RR {
	v4Up, _ := a.state.snapshot()
	var addrs []string
	if v4Up && len(a.zone.AHealthy) > 0 {
		addrs = a.zone.AHealthy
	} else {
		addrs = a.zone.AFallback
	}
	rrs := make([]dns.RR, 0, len(addrs))
	for _, ip := range addrs {
		if net.ParseIP(ip) == nil { continue }
		rrs = append(rrs, &dns.A{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeA, a.zone.TTLAnswer), A: net.ParseIP(ip).To4()})
	}
	return rrs
}

func (a *authority) addrAAAA() []dns.RR {
	_, v6Up := a.state.snapshot()
	var addrs []string
	if v6Up && len(a.zone.AAAAHealthy) > 0 {
		addrs = a.zone.AAAAHealthy
	} else {
		addrs = a.zone.AAAAFallback
	}
	rrs := make([]dns.RR, 0, len(addrs))
	for _, ip := range addrs {
		p := net.ParseIP(ip)
		if p == nil || p.To4() != nil { continue }
		rrs = append(rrs, &dns.AAAA{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeAAAA, a.zone.TTLAnswer), AAAA: p})
	}
	return rrs
}

func (a *authority) healthLoop() {
	interval := time.Duration(a.cfg.IntervalSec) * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		a.checkOnce()
		<-t.C
	}
}

func (a *authority) checkOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
	defer cancel()
	// Check v4 list: up if any IPv4 succeeds.
	v4ok := false
	for _, ip := range a.zone.AHealthy {
		if isIPv4(ip) && httpCheck(ctx, ip, a.zone.Health) == nil { v4ok = true; break }
	}
	a.state.setV4(v4ok, a.cfg.Rise, a.cfg.Fall)
	// Check v6 list
	v6ok := false
	for _, ip := range a.zone.AAAAHealthy {
		if !isIPv4(ip) && httpCheck(ctx, ip, a.zone.Health) == nil { v6ok = true; break }
	}
	a.state.setV6(v6ok, a.cfg.Rise, a.cfg.Fall)
}

func isIPv4(s string) bool { return net.ParseIP(s) != nil && net.ParseIP(s).To4() != nil }

func httpCheck(ctx context.Context, ip string, hc struct{ HostHeader, Path, SNI string; InsecureTLS bool }) error {
	if hc.Path == "" { hc.Path = "/health" }
	// Build URL by literal IP. IPv6 needs brackets.
	host := ip
	if strings.Contains(ip, ":") { host = "[" + ip + "]" }
	url := "https://" + host + hc.Path

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: hc.InsecureTLS, ServerName: firstNonEmpty(hc.SNI, hc.HostHeader)}}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if hc.HostHeader != "" { req.Host = hc.HostHeader }
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 { return nil }
	return errors.New(fmt.Sprintf("status %d", resp.StatusCode))
}

func firstNonEmpty(a, b string) string { if a != "" { return a }; return b }

