// minimal-gslb/main.go (feature update)
// Tiny authoritative DNS with health-based A/AAAA answers, flap damping,
// jittered checks, cooldown, dual-stack listeners, optional file logging,
// and support for shared records (TXT/MX/CAA/RP/SSHFP/SRV/NAPTR) plus an
// optional ALIAS/ANAME-like synth that resolves a target and returns A/AAAA.
//
// EDNS buffer size is honored (edns_buf). DNSSEC scaffolding is reserved for
// a future phase (keys & signing pipeline to be added before publishing DS).
//
// OS targets: Linux, macOS, Windows, *BSD (Go 1.21+).
// Build:   go build -trimpath -ldflags "-s -w" -o breathgslb
// Run:     ./breathgslb -config /etc/breathgslb/config.yaml
// Module:  github.com/akadatalimited/breathgslb

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/miekg/dns"
)

// HealthConfig holds per-zone health probe settings.
type HealthConfig struct {
	HostHeader  string `yaml:"host_header"`
	Path        string `yaml:"path"`
	SNI         string `yaml:"sni"`
	InsecureTLS bool   `yaml:"insecure_tls"`
}

// Config is the top-level YAML.
type Config struct {
	Listen      string `yaml:"listen"`        // e.g. ":53" or "0.0.0.0:5353" (port is extracted; dual-stack bind is used)
	Zones       []Zone `yaml:"zones"`

	TimeoutSec  int  `yaml:"timeout_sec"`
	IntervalSec int  `yaml:"interval_sec"`
	Rise        int  `yaml:"rise"`
	Fall        int  `yaml:"fall"`
	EDNSBuf     int  `yaml:"edns_buf"`
	LogQueries  bool `yaml:"log_queries"`

	// Softening knobs
	JitterMs    int    `yaml:"jitter_ms"`    // random 0..JitterMs added to each interval
	CooldownSec int    `yaml:"cooldown_sec"` // minimum time between state flips per family

	// Optional file logging (cross-platform). If empty, default is /var/log/breathgslb/breathgslb.log;
	// if creation fails, falls back to ./breathgslb.log
	LogFile     string `yaml:"log_file"`
}

// Shared record types. Name omitted => zone apex.
type TXTRecord struct {
	Name string   `yaml:"name,omitempty"`
	Text []string `yaml:"text"`
	TTL  uint32   `yaml:"ttl,omitempty"`
}

type MXRecord struct {
	Name       string `yaml:"name,omitempty"`
	Preference uint16 `yaml:"preference"`
	Exchange   string `yaml:"exchange"`
	TTL        uint32 `yaml:"ttl,omitempty"`
}

type CAARecord struct {
	Name  string `yaml:"name,omitempty"`
	Flag  uint8  `yaml:"flag"`
	Tag   string `yaml:"tag"`
	Value string `yaml:"value"`
	TTL   uint32 `yaml:"ttl,omitempty"`
}

type RPRecord struct {
	Name string `yaml:"name,omitempty"`
	Mbox string `yaml:"mbox"`
	Txt  string `yaml:"txt"`
	TTL  uint32 `yaml:"ttl,omitempty"`
}

type SSHFPRecord struct {
	Name        string `yaml:"name,omitempty"`
	Algorithm   uint8  `yaml:"algorithm"`
	Type        uint8  `yaml:"type"`
	Fingerprint string `yaml:"fingerprint"`
	TTL         uint32 `yaml:"ttl,omitempty"`
}

type SRVRecord struct {
	Name     string `yaml:"name"` // owner name (e.g., _sip._tcp.example.com.)
	Priority uint16 `yaml:"priority"`
	Weight   uint16 `yaml:"weight"`
	Port     uint16 `yaml:"port"`
	Target   string `yaml:"target"`
	TTL      uint32 `yaml:"ttl,omitempty"`
}

type NAPTRRecord struct {
	Name       string `yaml:"name"`
	Order      uint16 `yaml:"order"`
	Preference uint16 `yaml:"preference"`
	Flags      string `yaml:"flags"`
	Services   string `yaml:"services"`
	Regexp     string `yaml:"regexp"`
	Replacement string `yaml:"replacement"`
	TTL        uint32 `yaml:"ttl,omitempty"`
}

// Zone defines a single authoritative child zone served here.
type Zone struct {
	Name        string   `yaml:"name"`       // FQDN with trailing dot
	NS          []string `yaml:"ns"`         // FQDNs with trailing dots
	Admin       string   `yaml:"admin"`      // hostmaster email as hostmaster.example.com.
	TTLSOA      uint32   `yaml:"ttl_soa"`
	TTLAnswer   uint32   `yaml:"ttl_answer"`

	// Health-based addresses
	AHealthy     []string `yaml:"a_healthy"`
	AAAAHealthy  []string `yaml:"aaaa_healthy"`
	AFallback    []string `yaml:"a_fallback"`
	AAAAFallback []string `yaml:"aaaa_fallback"`

	// Optional ALIAS-like target (synthesizes A/AAAA from target if no A/AAAA given)
	Alias string `yaml:"alias,omitempty"`

	// Shared/static records
	TXT   []TXTRecord   `yaml:"txt,omitempty"`
	MX    []MXRecord    `yaml:"mx,omitempty"`
	CAA   []CAARecord   `yaml:"caa,omitempty"`
	RP    *RPRecord     `yaml:"rp,omitempty"`
	SSHFP []SSHFPRecord `yaml:"sshfp,omitempty"`
	SRV   []SRVRecord   `yaml:"srv,omitempty"`
	NAPTR []NAPTRRecord `yaml:"naptr,omitempty"`

	Health HealthConfig `yaml:"health"`
}

// state tracks per-zone health and damping counters.
type state struct {
	mu sync.RWMutex

	v4Up, v6Up           bool
	v4Rise, v4Fall       int
	v6Rise, v6Fall       int
	cooldown             time.Duration
	lastV4Change         time.Time
	lastV6Change         time.Time
}

func (s *state) snapshot() (v4, v6 bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v4Up, s.v6Up
}

func (s *state) setV4(obsUp bool, riseTarget, fallTarget int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if obsUp { s.v4Rise++; s.v4Fall = 0 } else { s.v4Fall++; s.v4Rise = 0 }
	proposed := s.v4Up
	if s.v4Rise >= riseTarget { proposed = true }
	if s.v4Fall >= fallTarget { proposed = false }
	if proposed != s.v4Up {
		if time.Since(s.lastV4Change) >= s.cooldown {
			s.v4Up = proposed
			s.lastV4Change = time.Now()
		}
	}
}

func (s *state) setV6(obsUp bool, riseTarget, fallTarget int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if obsUp { s.v6Rise++; s.v6Fall = 0 } else { s.v6Fall++; s.v6Rise = 0 }
	proposed := s.v6Up
	if s.v6Rise >= riseTarget { proposed = true }
	if s.v6Fall >= fallTarget { proposed = false }
	if proposed != s.v6Up {
		if time.Since(s.lastV6Change) >= s.cooldown {
			s.v6Up = proposed
			s.lastV6Change = time.Now()
		}
	}
}

// authority binds config + zone + state.
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

	// Defaults
	if cfg.TimeoutSec == 0 { cfg.TimeoutSec = 5 }
	if cfg.IntervalSec == 0 { cfg.IntervalSec = 8 }
	if cfg.Rise == 0 { cfg.Rise = 2 }
	if cfg.Fall == 0 { cfg.Fall = 4 }
	if cfg.EDNSBuf == 0 { cfg.EDNSBuf = 1232 }
	if cfg.JitterMs < 0 { cfg.JitterMs = 0 }
	if cfg.CooldownSec == 0 { cfg.CooldownSec = 25 }
	if cfg.LogFile == "" { cfg.LogFile = "/var/log/breathgslb/breathgslb.log" }

	// Initialize logging to file with fallback
	setupLogging(cfg.LogFile)
	log.Printf("breathgslb starting; interval=%ds rise=%d fall=%d cooldown=%ds jitter=%dms edns=%d", cfg.IntervalSec, cfg.Rise, cfg.Fall, cfg.CooldownSec, cfg.JitterMs, cfg.EDNSBuf)

	rand.Seed(time.Now().UnixNano())

	mux := dns.NewServeMux()
	for _, z := range cfg.Zones {
		zname := ensureDot(z.Name)
		st := &state{cooldown: time.Duration(cfg.CooldownSec) * time.Second}
		auth := &authority{cfg: cfg, zone: z, state: st}
		mux.HandleFunc(zname, auth.handle)
		go auth.healthLoop()
		log.Printf("serving zone %s", zname)
	}

	// Dual-stack listeners (derive port from cfg.Listen)
	port := derivePort(cfg.Listen)
	addrs := []struct{ netw, addr string }{
		{"udp4", "0.0.0.0:" + port},
		{"udp6", "[::]:" + port},
		{"tcp4", "0.0.0.0:" + port},
		{"tcp6", "[::]:" + port},
	}
	for _, a := range addrs {
		srv := &dns.Server{Net: a.netw, Addr: a.addr, Handler: dnsutil{cfg: cfg, inner: mux}}
		log.Printf("listening on %s %s", a.netw, a.addr)
		go func(s *dns.Server) {
			if err := s.ListenAndServe(); err != nil { log.Fatalf("listen %s %s: %v", s.Net, s.Addr, err) }
		}(srv)
	}
	select {}
}

func setupLogging(path string) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("warn: cannot create log dir %s: %v; falling back to ./breathgslb.log", dir, err)
		path = "./breathgslb.log"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("warn: cannot open log file %s: %v; using stderr only", path, err)
		return
	}
	mw := io.MultiWriter(os.Stderr, f)
	log.SetOutput(mw)
	log.SetFlags(0)
	log.SetPrefix("")
	log.Printf("logging to %s", path)
}

// dnsutil injects EDNS0 buffer hints.
type dnsutil struct{ cfg Config; inner dns.Handler }

func (d dnsutil) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if o := r.IsEdns0(); o != nil { o.SetUDPSize(uint16(d.cfg.EDNSBuf)) }
	d.inner.ServeDNS(w, r)
}

func (a *authority) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 { _ = w.WriteMsg(m); return }

	q := r.Question[0]
	name := ensureDot(q.Name)
	z := ensureDot(a.zone.Name)

	if a.cfg.LogQueries {
		log.Printf("query %s %s", name, dns.TypeToString[q.Qtype])
	}

	// SOA/NS at apex
	if name == z {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, a.soa())
		case dns.TypeNS:
			for _, ns := range a.zone.NS { m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)}) }
		}
	}

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, a.addrA(name)...)
	case dns.TypeAAAA:
		m.Answer = append(m.Answer, a.addrAAAA(name)...)
	case dns.TypeTXT:
		m.Answer = append(m.Answer, a.txtFor(name)...)
	case dns.TypeMX:
		m.Answer = append(m.Answer, a.mxFor(name)...)
	case dns.TypeCAA:
		m.Answer = append(m.Answer, a.caaFor(name)...)
	case dns.TypeRP:
		if rr := a.rpFor(name); rr != nil { m.Answer = append(m.Answer, rr) }
	case dns.TypeSSHFP:
		m.Answer = append(m.Answer, a.sshfpFor(name)...)
	case dns.TypeSRV:
		m.Answer = append(m.Answer, a.srvFor(name)...)
	case dns.TypeNAPTR:
		m.Answer = append(m.Answer, a.naptrFor(name)...)
	case dns.TypeSOA, dns.TypeNS:
		// already handled above
	default:
		m.Rcode = dns.RcodeNameError
	}

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

func ensureDot(s string) string { if !strings.HasSuffix(s, ".") { return s + "." }; return s }

// Address selection for a given owner name (currently apex only for GSLB; ALIAS can synthesize).
func (a *authority) addrA(owner string) []dns.RR {
	// Only apex gets GSLB/ALIAS; subnames are static-only for now.
	if ensureDot(owner) != ensureDot(a.zone.Name) {
		return nil
	}
	v4Up, _ := a.state.snapshot()
	var addrs []string
	if v4Up && len(a.zone.AHealthy) > 0 {
		addrs = a.zone.AHealthy
	} else if len(a.zone.AFallback) > 0 {
		addrs = a.zone.AFallback
	} else if a.zone.Alias != "" {
		// synthesize via alias target
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
		defer cancel()
		ips := aliasLookup(ctx, a.zone.Alias)
		for _, ip := range ips {
			if ip.To4() != nil {
				addrs = append(addrs, ip.String())
			}
		}
	}
	var rrs []dns.RR
	for _, ip := range addrs {
		p := net.ParseIP(ip)
		if p == nil || p.To4() == nil { continue }
		rrs = append(rrs, &dns.A{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeA, a.zone.TTLAnswer), A: p.To4()})
	}
	return rrs
}

func (a *authority) addrAAAA(owner string) []dns.RR {
	if ensureDot(owner) != ensureDot(a.zone.Name) {
		return nil
	}
	_, v6Up := a.state.snapshot()
	var addrs []string
	if v6Up && len(a.zone.AAAAHealthy) > 0 {
		addrs = a.zone.AAAAHealthy
	} else if len(a.zone.AAAAFallback) > 0 {
		addrs = a.zone.AAAAFallback
	} else if a.zone.Alias != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
		defer cancel()
		ips := aliasLookup(ctx, a.zone.Alias)
		for _, ip := range ips {
			if ip.To4() == nil {
				addrs = append(addrs, ip.String())
			}
		}
	}
	var rrs []dns.RR
	for _, ip := range addrs {
		p := net.ParseIP(ip)
		if p == nil || p.To4() != nil { continue }
		rrs = append(rrs, &dns.AAAA{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeAAAA, a.zone.TTLAnswer), AAAA: p})
	}
	return rrs
}

// Shared/static helpers
func (a *authority) txtFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, t := range a.zone.TXT {
		name := ensureDot(firstNonEmpty(t.Name, a.zone.Name))
		if name != owner { continue }
		ttl := t.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		rrs = append(rrs, &dns.TXT{Hdr: hdr(name, dns.TypeTXT, ttl), Txt: t.Text})
	}
	return rrs
}

func (a *authority) mxFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, mx := range a.zone.MX {
		name := ensureDot(firstNonEmpty(mx.Name, a.zone.Name))
		if name != owner { continue }
		ttl := mx.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		rrs = append(rrs, &dns.MX{Hdr: hdr(name, dns.TypeMX, ttl), Preference: mx.Preference, Mx: ensureDot(mx.Exchange)})
	}
	return rrs
}

func (a *authority) caaFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, c := range a.zone.CAA {
		name := ensureDot(firstNonEmpty(c.Name, a.zone.Name))
		if name != owner { continue }
		ttl := c.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		rrs = append(rrs, &dns.CAA{Hdr: hdr(name, dns.TypeCAA, ttl), Flag: c.Flag, Tag: c.Tag, Value: c.Value})
	}
	return rrs
}

func (a *authority) rpFor(owner string) dns.RR {
	owner = ensureDot(owner)
	if a.zone.RP == nil { return nil }
	name := ensureDot(firstNonEmpty(a.zone.RP.Name, a.zone.Name))
	if name != owner { return nil }
	ttl := a.zone.RP.TTL
	if ttl == 0 { ttl = a.zone.TTLAnswer }
	return &dns.RP{Hdr: hdr(name, dns.TypeRP, ttl), Mbox: ensureDot(a.zone.RP.Mbox), Txt: ensureDot(a.zone.RP.Txt)}
}

func (a *authority) sshfpFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, s := range a.zone.SSHFP {
		name := ensureDot(firstNonEmpty(s.Name, a.zone.Name))
		if name != owner { continue }
		ttl := s.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		rrs = append(rrs, &dns.SSHFP{Hdr: hdr(name, dns.TypeSSHFP, ttl), Algorithm: s.Algorithm, Type: s.Type, FingerPrint: s.Fingerprint})
	}
	return rrs
}

func (a *authority) srvFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, s := range a.zone.SRV {
		name := ensureDot(s.Name)
		if name == "." { name = ensureDot(a.zone.Name) }
		if name != owner { continue }
		ttl := s.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		rrs = append(rrs, &dns.SRV{Hdr: hdr(name, dns.TypeSRV, ttl), Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: ensureDot(s.Target)})
	}
	return rrs
}

func (a *authority) naptrFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, n := range a.zone.NAPTR {
		name := ensureDot(n.Name)
		if name == "." { name = ensureDot(a.zone.Name) }
		if name != owner { continue }
		ttl := n.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		rrs = append(rrs, &dns.NAPTR{Hdr: hdr(name, dns.TypeNAPTR, ttl), Order: n.Order, Preference: n.Preference, Flags: n.Flags, Service: n.Services, Regexp: n.Regexp, Replacement: ensureDot(n.Replacement)})
	}
	return rrs
}

func (a *authority) healthLoop() {
	base := time.Duration(a.cfg.IntervalSec) * time.Second
	if base <= 0 { base = 5 * time.Second }
	for {
		a.checkOnce()
		jitter := time.Duration(0)
		if a.cfg.JitterMs > 0 { jitter = time.Duration(rand.Intn(a.cfg.JitterMs+1)) * time.Millisecond }
		time.Sleep(base + jitter)
	}
}

func (a *authority) checkOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
	defer cancel()

	// v4: any-success policy; per-IP logging when enabled
	v4ok := false
	for _, ip := range a.zone.AHealthy {
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil { continue }
		err := httpCheck(ctx, ip, a.zone.Health)
		if a.cfg.LogQueries {
			if err != nil { log.Printf("health v4 DOWN %s: %v", ip, err) } else { log.Printf("health v4 UP %s", ip) }
		}
		if err == nil { v4ok = true; break }
	}
	prevV4, prevV6 := a.state.snapshot()
	a.state.setV4(v4ok, a.cfg.Rise, a.cfg.Fall)

	// v6: any-success policy
	v6ok := false
	for _, ip := range a.zone.AAAAHealthy {
		p := net.ParseIP(ip)
		if p == nil || p.To4() != nil { continue }
		err := httpCheck(ctx, ip, a.zone.Health)
		if a.cfg.LogQueries {
			if err != nil { log.Printf("health v6 DOWN %s: %v", ip, err) } else { log.Printf("health v6 UP %s", ip) }
		}
		if err == nil { v6ok = true; break }
	}
	a.state.setV6(v6ok, a.cfg.Rise, a.cfg.Fall)
	nowV4, nowV6 := a.state.snapshot()
	if a.cfg.LogQueries {
		if prevV4 != nowV4 { log.Printf("state v4 -> %v", nowV4) }
		if prevV6 != nowV6 { log.Printf("state v6 -> %v", nowV6) }
	}
}

func isIPv4(s string) bool { ip := net.ParseIP(s); return ip != nil && ip.To4() != nil }

func httpCheck(ctx context.Context, ip string, hc HealthConfig) error {
	path := hc.Path
	if path == "" { path = "/health" }
	// Literal-IP URL; bracket v6
	host := ip
	if strings.Contains(ip, ":") { host = "[" + ip + "]" }
	url := "https://" + host + path

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: hc.InsecureTLS, ServerName: firstNonEmpty(hc.SNI, hc.HostHeader)}}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if hc.HostHeader != "" { req.Host = hc.HostHeader }
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 { return nil }
	return fmt.Errorf("status %d", resp.StatusCode)
}

func aliasLookup(ctx context.Context, target string) []net.IP {
	target = strings.TrimSuffix(target, ".")
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil { return nil }
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs { ips = append(ips, a.IP) }
	return ips
}

func firstNonEmpty(a, b string) string { if a != "" { return a }; return b }

func derivePort(listen string) string {
	if listen == "" { return "53" }
	// Try SplitHostPort; if it fails, fallback to last-colon parse.
	_, port, err := net.SplitHostPort(listen)
	if err == nil && port != "" { return port }
	i := strings.LastIndex(listen, ":")
	if i >= 0 && i < len(listen)-1 { return listen[i+1:] }
	return "53"
}
