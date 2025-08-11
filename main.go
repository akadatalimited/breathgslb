// minimal-gslb/main.go (+reload +DNSSEC alpha)
// Tiny authoritative DNS with health-based A/AAAA answers, flap damping,
// jittered checks, cooldown, dual-stack listeners, optional file logging,
// shared records (TXT/MX/CAA/RP/SSHFP/SRV/NAPTR), ALIAS synth, **SIGHUP reload**, and
// **DNSSEC (alpha)**: online RRSIG for positive RRsets and DNSKEY; NSEC for
// existing names (NXRRSET). NSEC3 and full NXDOMAIN proofs planned next.
//
// EDNS buffer size is honored (edns_buf). DO-bit triggers DNSSEC material.
//
// Build:   go build -trimpath -ldflags "-s -w" -o breathgslb
// Run:     ./breathgslb -config /etc/breathgslb/config.yaml
// Module:  github.com/akadatalimited/breathgslb

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// ---- DNSSEC config ----

type DNSSECZoneConfig struct {
	Enable   bool   `yaml:"enable"`
	ZSKFile  string `yaml:"zsk_keyfile,omitempty"` // BIND-style prefix without extension or full path without extension; we'll add .key and .private
	KSKFile  string `yaml:"ksk_keyfile,omitempty"` // if empty, ZSKFile is used for both
	// Future: NSEC3 parameters
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

	Health HealthConfig    `yaml:"health"`
	DNSSEC *DNSSECZoneConfig `yaml:"dnssec,omitempty"`
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
	s.mu.RLock(); defer s.mu.RUnlock(); return s.v4Up, s.v6Up
}
func (s *state) setV4(obsUp bool, riseTarget, fallTarget int) {
	s.mu.Lock(); defer s.mu.Unlock()
	if obsUp { s.v4Rise++; s.v4Fall = 0 } else { s.v4Fall++; s.v4Rise = 0 }
	proposed := s.v4Up
	if s.v4Rise >= riseTarget { proposed = true }
	if s.v4Fall >= fallTarget { proposed = false }
	if proposed != s.v4Up && time.Since(s.lastV4Change) >= s.cooldown { s.v4Up = proposed; s.lastV4Change = time.Now() }
}
func (s *state) setV6(obsUp bool, riseTarget, fallTarget int) {
	s.mu.Lock(); defer s.mu.Unlock()
	if obsUp { s.v6Rise++; s.v6Fall = 0 } else { s.v6Fall++; s.v6Rise = 0 }
	proposed := s.v6Up
	if s.v6Rise >= riseTarget { proposed = true }
	if s.v6Fall >= fallTarget { proposed = false }
	if proposed != s.v6Up && time.Since(s.lastV6Change) >= s.cooldown { s.v6Up = proposed; s.lastV6Change = time.Now() }
}

// ---- DNSSEC runtime structures ----

type dnssecKeys struct {
	enabled bool
	zsk    *dns.DNSKEY
	zskPriv crypto.Signer
	ksk    *dns.DNSKEY // may equal zsk
	kskPriv crypto.Signer
}

// zoneIndex tracks owner names and type bitmaps for NSEC.

type zoneIndex struct {
	names []string                              // sorted, lowercased FQDNs
	types map[string]map[uint16]bool            // owner -> set of rrtypes present
}

// authority binds config + zone + state + dnssec + index and runs health.
type authority struct {
	cfg   *Config
	zone  Zone
	state *state

	ctx    context.Context
	cancel context.CancelFunc

	keys *dnssecKeys
	zidx *zoneIndex
}

// router is a dynamic handler wrapper we can hot-swap on HUP.
type router struct {
	inner atomic.Value // dns.Handler
	edns  atomic.Uint32
}

func (r *router) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if o := req.IsEdns0(); o != nil {
		o.SetUDPSize(uint16(r.edns.Load()))
	}
	h := r.inner.Load()
	if h == nil { _ = w.WriteMsg(new(dns.Msg)); return }
	h.(dns.Handler).ServeDNS(w, req)
}

// ---- globals for reload ----

var (
	current struct {
		mu    sync.Mutex
		cfg   *Config
		rt    *router
		logF  *os.File
		auths map[string]*authority // by zone name (fqdn)
	}
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "config.yaml", "path to YAML config")
	flag.Parse()

	// initial load
	cfg, err := loadConfig(cfgPath)
	if err != nil { log.Fatalf("read config: %v", err) }
	setupDefaults(cfg)

	// logging
	f := setupLogging(cfg.LogFile)

	rand.Seed(time.Now().UnixNano())

	rt := &router{}
	rt.edns.Store(uint32(cfg.EDNSBuf))

	mux, auths := buildMux(cfg)
	rt.inner.Store(mux)

	current.mu.Lock()
	current.cfg = cfg
	current.rt = rt
	current.logF = f
	current.auths = auths
	current.mu.Unlock()

	// listeners
	startListeners(rt, cfg)

	// signals: HUP reload, TERM/INT exit
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		s := <-sigc
		switch s {
		case syscall.SIGHUP:
			if err := reload(cfgPath); err != nil {
				log.Printf("reload failed: %v", err)
			} else {
				log.Printf("reloaded configuration")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("signal %v: shutting down", s)
			shutdown()
			return
		}
	}
}

func setupDefaults(cfg *Config) {
	if cfg.TimeoutSec == 0 { cfg.TimeoutSec = 5 }
	if cfg.IntervalSec == 0 { cfg.IntervalSec = 8 }
	if cfg.Rise == 0 { cfg.Rise = 2 }
	if cfg.Fall == 0 { cfg.Fall = 4 }
	if cfg.EDNSBuf == 0 { cfg.EDNSBuf = 1232 }
	if cfg.JitterMs < 0 { cfg.JitterMs = 0 }
	if cfg.CooldownSec == 0 { cfg.CooldownSec = 25 }
	if cfg.LogFile == "" { cfg.LogFile = "/var/log/breathgslb/breathgslb.log" }
}

func setupLogging(path string) *os.File {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("warn: cannot create log dir %s: %v; falling back to ./breathgslb.log", dir, err)
		path = "./breathgslb.log"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("warn: cannot open log file %s: %v; using stderr only", path, err)
		return nil
	}
	mw := io.MultiWriter(os.Stderr, f)
	log.SetOutput(mw)
	log.SetFlags(0)
	log.SetPrefix("")
	log.Printf("logging to %s", path)
	return f
}

func reopenLogging(newPath string) {
	current.mu.Lock(); defer current.mu.Unlock()
	if current.cfg.LogFile == newPath {
		return
	}
	if current.logF != nil { _ = current.logF.Close() }
	current.logF = setupLogging(newPath)
	current.cfg.LogFile = newPath
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil { return nil, err }
	return &cfg, nil
}

func buildMux(cfg *Config) (dns.Handler, map[string]*authority) {
	mux := dns.NewServeMux()
	auths := make(map[string]*authority)
	for _, z := range cfg.Zones {
		zname := ensureDot(z.Name)
		ctx, cancel := context.WithCancel(context.Background())
		st := &state{cooldown: time.Duration(cfg.CooldownSec) * time.Second}
		auth := &authority{cfg: cfg, zone: z, state: st, ctx: ctx, cancel: cancel}
		// DNSSEC keys & index
		auth.keys = loadDNSSEC(z)
		auth.zidx = buildIndex(z)

		mux.HandleFunc(zname, auth.handle)
		auths[zname] = auth
		go auth.healthLoop()
		log.Printf("serving zone %s", zname)
	}
	return mux, auths
}

func startListeners(rt *router, cfg *Config) {
	port := derivePort(cfg.Listen)
	addrs := []struct{ netw, addr string }{{"udp4", "0.0.0.0:" + port}, {"udp6", "[::]:" + port}, {"tcp4", "0.0.0.0:" + port}, {"tcp6", "[::]:" + port}}
	for _, a := range addrs {
		srv := &dns.Server{Net: a.netw, Addr: a.addr, Handler: rt}
		log.Printf("listening on %s %s", a.netw, a.addr)
		go func(s *dns.Server) {
			if err := s.ListenAndServe(); err != nil { log.Fatalf("listen %s %s: %v", s.Net, s.Addr, err) }
		}(srv)
	}
}

func reload(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil { return err }
	setupDefaults(cfg)

	// swap handler
	mux, auths := buildMux(cfg)

	current.mu.Lock()
	old := current.auths
	current.rt.inner.Store(mux)
	current.rt.edns.Store(uint32(cfg.EDNSBuf))
	current.cfg = cfg
	current.auths = auths
	current.mu.Unlock()

	// stop old health loops
	for _, a := range old { a.cancel() }

	// maybe reopen log file
	reopenLogging(cfg.LogFile)
	return nil
}

func shutdown() {
	current.mu.Lock(); defer current.mu.Unlock()
	for _, a := range current.auths { a.cancel() }
	if current.logF != nil { _ = current.logF.Close() }
}

// ---- request handling ----

func (a *authority) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 { _ = w.WriteMsg(m); return }
	q := r.Question[0]
	name := ensureDot(q.Name)
	z := ensureDot(a.zone.Name)

	if a.cfg.LogQueries { log.Printf("query %s %s", strings.ToLower(name), dns.TypeToString[q.Qtype]) }

	// Basic apex handling for SOA/NS/DNSKEY
	if name == z {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, a.soa())
		case dns.TypeNS:
			for _, ns := range a.zone.NS { m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)}) }
		case dns.TypeDNSKEY:
			if a.keys != nil && a.keys.enabled {
				for _, k := range a.dnskeyRRSet() { m.Answer = append(m.Answer, k) }
				if wantDNSSEC(r) { m.Answer = a.signAll(m.Answer) }
			}
			}
	}

	// Regular QTYPEs
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
	}

	// If nothing in Answer, include NS/SOA in Authority as before
	if len(m.Answer) == 0 {
		for _, ns := range a.zone.NS { m.Ns = append(m.Ns, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)}) }
		m.Ns = append(m.Ns, a.soa())

		// NXRRSET proof with NSEC (alpha)
		if wantDNSSEC(r) && a.keys != nil && a.keys.enabled {
			if a.zidx != nil && a.zidx.hasName(name) {
				if nsec := a.makeNSEC(name); nsec != nil {
					m.Ns = append(m.Ns, nsec)
					/* signed later by a.signAll */
				}
			}
		}
	}

	// Sign positive RRsets when DO-bit set
	if wantDNSSEC(r) && a.keys != nil && a.keys.enabled {
		m.Answer = a.signAll(m.Answer)
		m.Ns = a.signAll(m.Ns)
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
func ownerName(apex, s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == "@" { return ensureDot(apex) }
	return ensureDot(s)
}

// Address selection for a given owner name (currently apex only for GSLB; ALIAS can synthesize).
func (a *authority) addrA(owner string) []dns.RR {
	if ensureDot(owner) != ensureDot(a.zone.Name) { return nil }
	v4Up, _ := a.state.snapshot()
	var addrs []string
	if v4Up && len(a.zone.AHealthy) > 0 { addrs = a.zone.AHealthy } else if len(a.zone.AFallback) > 0 { addrs = a.zone.AFallback } else if a.zone.Alias != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second); defer cancel()
		ips := aliasLookup(ctx, a.zone.Alias)
		for _, ip := range ips { if ip.To4() != nil { addrs = append(addrs, ip.String()) } }
	}
	var rrs []dns.RR
	for _, ip := range addrs {
		p := net.ParseIP(ip); if p == nil || p.To4() == nil { continue }
		rrs = append(rrs, &dns.A{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeA, a.zone.TTLAnswer), A: p.To4()})
	}
	return rrs
}

func (a *authority) addrAAAA(owner string) []dns.RR {
	if ensureDot(owner) != ensureDot(a.zone.Name) { return nil }
	_, v6Up := a.state.snapshot()
	var addrs []string
	if v6Up && len(a.zone.AAAAHealthy) > 0 { addrs = a.zone.AAAAHealthy } else if len(a.zone.AAAAFallback) > 0 { addrs = a.zone.AAAAFallback } else if a.zone.Alias != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second); defer cancel()
		ips := aliasLookup(ctx, a.zone.Alias)
		for _, ip := range ips { if ip.To4() == nil { addrs = append(addrs, ip.String()) } }
	}
	var rrs []dns.RR
	for _, ip := range addrs {
		p := net.ParseIP(ip); if p == nil || p.To4() != nil { continue }
		rrs = append(rrs, &dns.AAAA{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeAAAA, a.zone.TTLAnswer), AAAA: p})
	}
	return rrs
}

// Shared/static helpers
func (a *authority) txtFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, t := range a.zone.TXT {
		name := ownerName(a.zone.Name, t.Name)
		if name != owner { continue }
		ttl := t.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		if len(t.Text) > 0 { rrs = append(rrs, &dns.TXT{Hdr: hdr(name, dns.TypeTXT, ttl), Txt: t.Text}) }
	}
	return rrs
}

func (a *authority) mxFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, mx := range a.zone.MX {
		name := ownerName(a.zone.Name, mx.Name)
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
		name := ownerName(a.zone.Name, c.Name)
		if name != owner { continue }
		ttl := c.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
		rrs = append(rrs, &dns.CAA{Hdr: hdr(name, dns.TypeCAA, ttl), Flag: c.Flag, Tag: c.Tag, Value: c.Value})
	}
	return rrs
}

func (a *authority) rpFor(owner string) dns.RR {
	owner = ensureDot(owner)
	if a.zone.RP == nil { return nil }
	name := ownerName(a.zone.Name, a.zone.RP.Name)
	if name != owner { return nil }
	ttl := a.zone.RP.TTL; if ttl == 0 { ttl = a.zone.TTLAnswer }
	return &dns.RP{Hdr: hdr(name, dns.TypeRP, ttl), Mbox: ensureDot(a.zone.RP.Mbox), Txt: ensureDot(a.zone.RP.Txt)}
}

func (a *authority) sshfpFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, s := range a.zone.SSHFP {
		name := ownerName(a.zone.Name, s.Name)
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
		name := ownerName(a.zone.Name, s.Name)
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
		name := ownerName(a.zone.Name, n.Name)
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
		select {
		case <-a.ctx.Done():
			return
		default:
			// check once
			a.checkOnce()
			jitter := time.Duration(0)
			if a.cfg.JitterMs > 0 { jitter = time.Duration(rand.Intn(a.cfg.JitterMs+1)) * time.Millisecond }
			time.Sleep(base + jitter)
		}
	}
}

func (a *authority) checkOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
	defer cancel()
	// v4
	v4ok := false
	for _, ip := range a.zone.AHealthy {
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil { continue }
		err := httpCheck(ctx, ip, a.zone.Health)
		if a.cfg.LogQueries { if err != nil { log.Printf("health v4 DOWN %s: %v", ip, err) } else { log.Printf("health v4 UP %s", ip) } }
		if err == nil { v4ok = true; break }
	}
	prevV4, prevV6 := a.state.snapshot()
	a.state.setV4(v4ok, a.cfg.Rise, a.cfg.Fall)
	// v6
	v6ok := false
	for _, ip := range a.zone.AAAAHealthy {
		p := net.ParseIP(ip); if p == nil || p.To4() != nil { continue }
		err := httpCheck(ctx, ip, a.zone.Health)
		if a.cfg.LogQueries { if err != nil { log.Printf("health v6 DOWN %s: %v", ip, err) } else { log.Printf("health v6 UP %s", ip) } }
		if err == nil { v6ok = true; break }
	}
	a.state.setV6(v6ok, a.cfg.Rise, a.cfg.Fall)
	nowV4, nowV6 := a.state.snapshot()
	if a.cfg.LogQueries {
		if prevV4 != nowV4 { log.Printf("state v4 -> %v", nowV4) }
		if prevV6 != nowV6 { log.Printf("state v6 -> %v", nowV6) }
	}
}

func httpCheck(ctx context.Context, ip string, hc HealthConfig) error {
	path := hc.Path; if path == "" { path = "/health" }
	host := ip; if strings.Contains(ip, ":") { host = "[" + ip + "]" }
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
	_, port, err := net.SplitHostPort(listen)
	if err == nil && port != "" { return port }
	i := strings.LastIndex(listen, ":")
	if i >= 0 && i < len(listen)-1 { return listen[i+1:] }
	return "53"
}

// ---- DNSSEC helpers ----

func wantDNSSEC(r *dns.Msg) bool {
	if o := r.IsEdns0(); o != nil { return o.Do() }
	return false
}

func loadDNSSEC(z Zone) *dnssecKeys {
	if z.DNSSEC == nil || !z.DNSSEC.Enable { return &dnssecKeys{enabled: false} }
	baseZ := strings.TrimSuffix(ensureDot(z.Name), ".")
	zsk := z.DNSSEC.ZSKFile
	ksk := z.DNSSEC.KSKFile
	if zsk == "" { return &dnssecKeys{enabled: false} }
	if ksk == "" { ksk = zsk }
	zk, zpriv, err := parseBindKeyPair(baseZ, zsk)
	if err != nil { log.Printf("dnssec zsk load failed: %v", err); return &dnssecKeys{enabled: false} }
	kk, kpriv, err := parseBindKeyPair(baseZ, ksk)
	if err != nil { log.Printf("dnssec ksk load failed: %v", err); return &dnssecKeys{enabled: false} }
	return &dnssecKeys{enabled: true, zsk: zk, zskPriv: zpriv, ksk: kk, kskPriv: kpriv}
}

// Expect pub in <prefix>.key and private in <prefix>.private
func parseBindKeyPair(zone string, prefix string) (*dns.DNSKEY, crypto.Signer, error) {
	pubPath := prefix
	privPath := prefix
	if !strings.HasSuffix(pubPath, ".key") {
		pubPath += ".key"
	}
	if !strings.HasSuffix(privPath, ".private") {
		privPath += ".private"
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil { return nil, nil, err }
	rr, err := dns.NewRR(string(pubData))
	if err != nil { return nil, nil, err }
	dk, ok := rr.(*dns.DNSKEY)
	if !ok { return nil, nil, fmt.Errorf("not a DNSKEY in %s", pubPath) }
	f, err := os.Open(privPath)
	if err != nil { return nil, nil, err }
	defer f.Close()
	privAny, err := dk.ReadPrivateKey(f, privPath)
	if err != nil { return nil, nil, err }
	signer, ok := privAny.(crypto.Signer)
	if !ok { return nil, nil, fmt.Errorf("private key %s does not implement crypto.Signer", privPath) }
	return dk, signer, nil
}

func (a *authority) dnskeyRRSet() []dns.RR {
	if a.keys == nil || !a.keys.enabled { return nil }
	var out []dns.RR
	if a.keys.zsk != nil { out = append(out, a.keys.zsk) }
	if a.keys.ksk != nil && a.keys.ksk != a.keys.zsk { out = append(out, a.keys.ksk) }
	for i := range out {
		out[i].Header().Name = ensureDot(a.zone.Name)
		out[i].Header().Ttl = a.zone.TTLAnswer
	}
	return out
}

// signAll walks over rrs and appends RRSIGs per RRset type/name (ZSK; DNSKEY uses KSK)
func (a *authority) signAll(in []dns.RR) []dns.RR {
	if a.keys == nil || !a.keys.enabled { return in }
	if len(in) == 0 { return in }

	// group by name+type, but carry through any pre-existing RRSIGs untouched
	groups := map[string][]dns.RR{}
	var out []dns.RR
	for _, rr := range in {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			out = append(out, rr)
			continue
		}
		k := strings.ToLower(rr.Header().Name) + ":" + fmt.Sprint(rr.Header().Rrtype)
		groups[k] = append(groups[k], rr)
	}

	for _, g := range groups {
		out = append(out, g...)
		// pick key: DNSKEY RRset uses KSK, others use ZSK
		key := a.keys.zsk
		priv := a.keys.zskPriv
		if len(g) > 0 && g[0].Header().Rrtype == dns.TypeDNSKEY {
			key = a.keys.ksk
			priv = a.keys.kskPriv
		}
		if key == nil || priv == nil {
			log.Printf("dnssec sign skipped for %s/%d: missing key", g[0].Header().Name, g[0].Header().Rrtype)
			continue
		}
		sig := a.makeRRSIG(g, key)
		if err := sig.Sign(priv, g); err == nil {
			out = append(out, sig)
		} else {
			log.Printf("dnssec sign error for %s/%d: %v", g[0].Header().Name, g[0].Header().Rrtype, err)
		}
	}
	return out
}

func (a *authority) makeRRSIG(rrset []dns.RR, key *dns.DNSKEY) *dns.RRSIG {
	name := rrset[0].Header().Name
	ttl := rrset[0].Header().Ttl
	labels := uint8(strings.Count(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(name), "."), "."), ".") + 1)
	// validity: now-5m .. now+6h
	now := time.Now().UTC()
	incep := uint32(now.Add(-5 * time.Minute).Unix())
	exp := uint32(now.Add(6 * time.Hour).Unix())
	return &dns.RRSIG{
		Hdr:       hdr(name, dns.TypeRRSIG, ttl),
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm: key.Algorithm,
		Labels:    labels,
		OrigTtl:   ttl,
		Expiration: exp,
		Inception:  incep,
		KeyTag:    key.KeyTag(),
		SignerName: ensureDot(a.zone.Name),
	}
}

// NSEC support for existing names only (NXRRSET). We'll extend to full NXDOMAIN later.
func (a *authority) makeNSEC(owner string) dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	if a.zidx == nil { return nil }
	idx := a.zidx
	if !idx.hasName(owner) { return nil }
	next := idx.nextName(owner)
	bm := idx.typeBitmap(owner)
	return &dns.NSEC{Hdr: hdr(ensureDot(owner), dns.TypeNSEC, a.zone.TTLAnswer), NextDomain: ensureDot(next), TypeBitMap: bm}
}

// ---- zone index helpers ----

func buildIndex(z Zone) *zoneIndex {
	m := map[string]map[uint16]bool{}
	add := func(name string, t uint16) {
		name = strings.ToLower(ensureDot(name))
		if m[name] == nil { m[name] = map[uint16]bool{} }
		m[name][t] = true
	}
	zname := ensureDot(z.Name)
	add(zname, dns.TypeSOA)
	add(zname, dns.TypeNS)
	// potential A/AAAA at apex
	if len(z.AHealthy)+len(z.AFallback) > 0 { add(zname, dns.TypeA) }
	if len(z.AAAAHealthy)+len(z.AAAAFallback) > 0 { add(zname, dns.TypeAAAA) }
	for _, t := range z.TXT { add(ownerName(z.Name, t.Name), dns.TypeTXT) }
	for _, mx := range z.MX { add(ownerName(z.Name, mx.Name), dns.TypeMX) }
	for _, c := range z.CAA { add(ownerName(z.Name, c.Name), dns.TypeCAA) }
	if z.RP != nil { add(ownerName(z.Name, z.RP.Name), dns.TypeRP) }
	for _, s := range z.SSHFP { add(ownerName(z.Name, s.Name), dns.TypeSSHFP) }
	for _, s := range z.SRV { add(ownerName(z.Name, s.Name), dns.TypeSRV) }
	for _, n := range z.NAPTR { add(ownerName(z.Name, n.Name), dns.TypeNAPTR) }
	// if DNSSEC enabled, DNSKEY at apex
	if z.DNSSEC != nil && z.DNSSEC.Enable { add(zname, dns.TypeDNSKEY); add(zname, dns.TypeRRSIG) }
	// sort names
	ns := make([]string, 0, len(m))
	for k := range m { ns = append(ns, ensureDot(strings.ToLower(k))) }
	sort.Strings(ns)
	return &zoneIndex{names: ns, types: m}
}

func (z *zoneIndex) hasName(owner string) bool {
	owner = strings.ToLower(ensureDot(owner))
	_, ok := z.types[owner]
	return ok
}

func (z *zoneIndex) nextName(owner string) string {
	owner = strings.ToLower(ensureDot(owner))
	if len(z.names) == 0 { return owner }
	for i, n := range z.names {
		if n == owner { return z.names[(i+1)%len(z.names)] }
	}
	// not found, return first
	return z.names[0]
}

func (z *zoneIndex) typeBitmap(owner string) []uint16 {
	owner = strings.ToLower(ensureDot(owner))
	m := z.types[owner]
	if m == nil { return nil }
	var out []uint16
	for t := range m { out = append(out, t) }
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
