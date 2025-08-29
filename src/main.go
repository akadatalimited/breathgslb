package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/akadatalimited/breathgslb/src/dnsserver"
	"github.com/akadatalimited/breathgslb/src/doc"
	"github.com/akadatalimited/breathgslb/src/healthcheck"
	"github.com/akadatalimited/breathgslb/src/logging"
	"github.com/miekg/dns"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

var version = "dev"

func init() {
	version = strings.TrimSpace(version)
	if buildOS == "" {
		buildOS = runtime.GOOS
	}
}

var (
	serialDir = "."
	serialNow = func() uint32 { return uint32(time.Now().Unix()) }
)

func serialPath(zone string) string {
	name := strings.TrimSuffix(ensureDot(zone), ".")
	name = strings.ReplaceAll(name, "/", "_")
	return filepath.Join(serialDir, name+".serial")
}

func nextSerial(zone string) uint32 {
	now := serialNow()
	path := serialPath(zone)
	var prev uint64
	if b, err := os.ReadFile(path); err == nil {
		prev, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	}
	serial := now
	if serial <= uint32(prev) {
		serial = uint32(prev) + 1
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(strconv.FormatUint(uint64(serial), 10)), 0o644)
	return serial
}

// ---- state: per-tier, per-family ----

type famState struct {
	up         bool
	rise, fall int
	lastChange time.Time
}

type tierState struct {
	v4 famState
	v6 famState
}

type state struct {
	mu       sync.RWMutex
	cooldown time.Duration
	master   tierState
	standby  tierState
}

func (s *state) snapshot() (mV4, mV6, sV4, sV6 bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.master.v4.up, s.master.v6.up, s.standby.v4.up, s.standby.v6.up
}

func (s *state) set(tier string, ipv6 bool, obsUp bool, riseTarget, fallTarget int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f *famState
	if tier == "master" {
		if ipv6 {
			f = &s.master.v6
		} else {
			f = &s.master.v4
		}
	} else { // standby
		if ipv6 {
			f = &s.standby.v6
		} else {
			f = &s.standby.v4
		}
	}
	if obsUp {
		f.rise++
		f.fall = 0
	} else {
		f.fall++
		f.rise = 0
	}
	proposed := f.up
	if f.rise >= riseTarget {
		proposed = true
	}
	if f.fall >= fallTarget {
		proposed = false
	}
	if proposed != f.up && time.Since(f.lastChange) >= s.cooldown {
		f.up = proposed
		f.lastChange = time.Now()
	}
}

// ---- DNSSEC runtime structures ----

type dnssecKeys struct {
	enabled bool
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer
	ksk     *dns.DNSKEY // may equal zsk
	kskPriv crypto.Signer
}

// zoneIndex tracks owner names and type bitmaps for NSEC.

// parsed local CIDRs per tier

type parsedCIDRs struct {
	rfc []*net.IPNet
	ula []*net.IPNet
}

type tierCIDR struct {
	master   parsedCIDRs
	standby  parsedCIDRs
	fallback parsedCIDRs
}

// Geo resolver & cache

type geoResolver struct {
	db               *maxminddb.Reader
	preferRegistered bool
	mu               sync.RWMutex
	cache            map[string]geoCacheEntry
	ttl              time.Duration
}

type geoCacheEntry struct {
	country, continent string
	exp                time.Time
}

type mmdbCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

func newGeoResolver(c *GeoIPConfig) *geoResolver {
	if c == nil || !c.Enabled || c.Database == "" {
		return nil
	}
	db, err := maxminddb.Open(c.Database)
	if err != nil {
		log.Printf("geoip: open %s failed: %v", c.Database, err)
		return nil
	}
	ttl := time.Duration(600) * time.Second
	if c.CacheTTLSec > 0 {
		ttl = time.Duration(c.CacheTTLSec) * time.Second
	}
	preferRegistered := true
	if strings.ToLower(strings.TrimSpace(c.PreferField)) == "country" {
		preferRegistered = false
	}
	return &geoResolver{db: db, preferRegistered: preferRegistered, cache: make(map[string]geoCacheEntry), ttl: ttl}
}

func (g *geoResolver) Close() {
	if g == nil || g.db == nil {
		return
	}
	_ = g.db.Close()
}

func (g *geoResolver) lookup(ip net.IP) (country, continent string, ok bool) {
	if g == nil || g.db == nil || ip == nil {
		return "", "", false
	}
	key := ip.String()
	now := time.Now()
	g.mu.RLock()
	if e, okc := g.cache[key]; okc && now.Before(e.exp) {
		g.mu.RUnlock()
		return e.country, e.continent, true
	}
	g.mu.RUnlock()
	var rec mmdbCountry
	if err := g.db.Lookup(ip, &rec); err != nil {
		return "", "", false
	}
	cc := rec.Country.ISOCode
	if g.preferRegistered && rec.RegisteredCountry.ISOCode != "" {
		cc = rec.RegisteredCountry.ISOCode
	}
	cont := rec.Continent.Code
	g.mu.Lock()
	g.cache[key] = geoCacheEntry{country: strings.ToUpper(cc), continent: strings.ToUpper(cont), exp: now.Add(g.ttl)}
	g.mu.Unlock()
	return strings.ToUpper(cc), strings.ToUpper(cont), true
}

// authority binds config + zone + state + dnssec + index and runs health.

type authority struct {
	cfg   *Config
	zone  Zone
	state *state

	serial uint32

	ixfr *ixfrDelta

	ctx    context.Context
	cancel context.CancelFunc

	keys *dnssecKeys
	zidx *zoneIndex

	cidrs tierCIDR
	geo   *geoResolver

	persistA    sync.Map
	persistAAAA sync.Map
	rrA         atomic.Uint64
	rrAAAA      atomic.Uint64

	// secondary zone data
	mu      sync.RWMutex
	records map[string][]dns.RR
	axfrRRs []dns.RR
	soaRR   *dns.SOA

	// parsed CIDRs for geo_answers
	geoCIDR struct {
		country   map[string]parsedCIDRs
		continent map[string]parsedCIDRs
	}
}

type persistEntry struct {
	ip  string
	exp time.Time
}

type ixfrDelta struct {
	old *dns.SOA
	del []dns.RR
	new *dns.SOA
	add []dns.RR
}

// router is a dynamic handler wrapper we can hot-swap on HUP.

type router struct {
	inner atomic.Value // dns.Handler
	edns  atomic.Uint32
}

func (r *router) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	if o := req.IsEdns0(); o != nil {
		o.SetUDPSize(uint16(r.edns.Load()))
	}
	h := r.inner.Load()
	if h == nil {
		_ = w.WriteMsg(new(dns.Msg))
		recordLatency(time.Since(start))
		return
	}
	h.(dns.Handler).ServeDNS(w, req)
	recordLatency(time.Since(start))
}

// ---- globals for reload ----

var (
	current struct {
		mu    sync.Mutex
		cfg   *Config
		rt    *router
		logW  io.WriteCloser
		auths map[string]*authority // by zone name (fqdn)
		geo   *geoResolver
	}
	adminAPIToken string
	startTime     = time.Now()

	statsMu        sync.RWMutex
	memStatsRecent []runtime.MemStats
	latencyRecent  []time.Duration
	sup            *supervisor
)

const statsKeep = 60

type supState struct {
	Running  bool      `json:"running"`
	Restarts int       `json:"restarts"`
	LastExit time.Time `json:"last_exit,omitempty"`
}

type supervisor struct {
	mu     sync.RWMutex
	states map[string]supState
}

func newSupervisor() *supervisor {
	return &supervisor{states: make(map[string]supState)}
}

func (s *supervisor) set(name string, st supState) {
	s.mu.Lock()
	s.states[name] = st
	s.mu.Unlock()
}

func (s *supervisor) update(name string, running, restarted bool) {
	s.mu.Lock()
	st := s.states[name]
	st.Running = running
	if restarted {
		st.Restarts++
		st.LastExit = time.Now()
	} else if !running {
		st.LastExit = time.Now()
	}
	s.states[name] = st
	s.mu.Unlock()
}

func (s *supervisor) snapshot() map[string]supState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[string]supState, len(s.states))
	for k, v := range s.states {
		m[k] = v
	}
	return m
}

func (s *supervisor) watch(ctx context.Context, name string, fn func()) {
	s.mu.Lock()
	if _, ok := s.states[name]; !ok {
		s.states[name] = supState{}
	}
	s.mu.Unlock()
	go func() {
		backoff := time.Second
		for {
			s.update(name, true, false)
			done := make(chan struct{})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("%s panic: %v", name, r)
					}
					close(done)
				}()
				fn()
			}()
			select {
			case <-ctx.Done():
				s.update(name, false, false)
				return
			case <-done:
				if ctx.Err() != nil {
					s.update(name, false, false)
					return
				}
				s.update(name, false, true)
				log.Printf("supervisor: %s exited unexpectedly; restarting in %v", name, backoff)
				time.Sleep(backoff)
				if backoff < 30*time.Second {
					backoff *= 2
				}
			}
		}
	}()
}

func recordLatency(d time.Duration) {
	statsMu.Lock()
	if len(latencyRecent) >= statsKeep {
		copy(latencyRecent, latencyRecent[1:])
		latencyRecent = latencyRecent[:statsKeep-1]
	}
	latencyRecent = append(latencyRecent, d)
	statsMu.Unlock()
}

func sampleMemStats() {
	ticker := time.NewTicker(10 * time.Second)
	for {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		statsMu.Lock()
		if len(memStatsRecent) >= statsKeep {
			copy(memStatsRecent, memStatsRecent[1:])
			memStatsRecent = memStatsRecent[:statsKeep-1]
		}
		memStatsRecent = append(memStatsRecent, m)
		statsMu.Unlock()
		<-ticker.C
	}
}

func apiAddrs(ifaces []string, port int) []string {
	p := strconv.Itoa(port)
	seen := map[string]bool{}
	var addrs []string
	for _, ifn := range ifaces {
		ifn = strings.TrimSpace(ifn)
		if ifn == "" {
			continue
		}
		ifi, err := net.InterfaceByName(ifn)
		if err != nil {
			log.Printf("warn: api interface %s not found: %v", ifn, err)
			continue
		}
		addrsList, err := ifi.Addrs()
		if err != nil {
			log.Printf("warn: cannot read addrs for %s: %v", ifn, err)
			continue
		}
		for _, a := range addrsList {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
				continue
			}
			addr := ip.String()
			if ip.To4() != nil {
				addr = addr + ":" + p
			} else {
				addr = "[" + addr + "]:" + p
			}
			if !seen[addr] {
				addrs = append(addrs, addr)
				seen[addr] = true
			}
		}
	}
	if len(addrs) == 0 {
		addrs = append(addrs, ":"+p)
	}
	return addrs
}

func aboutText() string {
	return fmt.Sprintf(`BreathGSLB - V%s %s Release

A Native IPv6 DNS Global Server Loadbalancer thats RFC and ULA Local Networks
With Primary, Secondary and Fallback servers fully health checked,
API Endpoint pprof debug server and memory GC
Designed from the ground up for IPv6 with full legacy IPv4 Support
(C) 2025 Breath Technology //breathtechnology.co.uk

`, version, buildOS)
}

func printSupportStatus() {
	supported, days := supportStatus()
	status := "Unsupported"
	if supported {
		status = "Supported"
	}
	fmt.Printf("%s (%d days remaining)\n", status, days)
	if supported {
		fmt.Println("dns-support@breathtechnology.co.uk")
	}
}

func supportRequest() error {
	fmt.Println("support request initiated")
	return nil
}

func main() {
	var cfgPath string
	var apiListen string
	var supervisor string
	var apiToken string
	var apiCert string
	var apiKey string
	var activateKey string
	var debugPprof bool
	var showHelp bool
	var showAbout bool
	var supportReq bool
	var licensePayload string

	flag.StringVar(&cfgPath, "config", "config.yaml", "path to YAML config")
	flag.StringVar(&cfgPath, "c", "config.yaml", "path to YAML config")
	flag.StringVar(&apiListen, "api-listen", "", "HTTPS listen address for admin API")
	flag.StringVar(&apiListen, "al", "", "HTTPS listen address for admin API")
	flag.StringVar(&supervisor, "supervisor", "", "supervisor notification target")
	flag.StringVar(&supervisor, "s", "", "supervisor notification target")
	flag.StringVar(&apiToken, "api-token", "", "admin API bearer token")
	flag.StringVar(&apiToken, "at", "", "admin API bearer token")
	flag.StringVar(&apiCert, "api-cert", "", "TLS certificate for admin API")
	flag.StringVar(&apiCert, "ac", "", "TLS certificate for admin API")
	flag.StringVar(&apiKey, "api-key", "", "TLS key for admin API")
	flag.StringVar(&apiKey, "ak", "", "TLS key for admin API")
	flag.StringVar(&activateKey, "activate", "", "activate license with provided key and exit")
	flag.StringVar(&activateKey, "k", "", "activate license with provided key and exit")
	flag.StringVar(&licensePayload, "license-payload", "", "base64-encoded license payload")
	flag.StringVar(&licensePayload, "lp", "", "base64-encoded license payload")
	flag.BoolVar(&debugPprof, "debug-pprof", false, "enable pprof debug server on localhost:6060")
	flag.BoolVar(&debugPprof, "d", false, "enable pprof debug server on localhost:6060")
	flag.BoolVar(&showHelp, "help", false, "returns help for BreathGSLB")
	flag.BoolVar(&showHelp, "h", false, "returns help for BreathGSLB")
	flag.BoolVar(&showAbout, "about", false, "returns a detailed about page")
	flag.BoolVar(&showAbout, "a", false, "returns a detailed about page")
	flag.BoolVar(&supportReq, "support-request", false, "create a support request and exit")
	flag.BoolVar(&supportReq, "sr", false, "create a support request and exit")

	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), aboutText())
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprint(flag.CommandLine.Output(), "-ac --api-cert string\nTLS certificate for admin API\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-ak --api-key string\nTLS key for admin API\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-al --api-listen string\nHTTPS listen address for admin API\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-at --api-token string\nadmin API bearer token\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-c --config string\npath to YAML config (default \"config.yaml\")\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-d --debug-pprof\nenable pprof debug server on localhost:6060\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-s --supervisor string\nsupervisor notification target\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-k --activate string\nactivate license with provided key and exit\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-lp --license-payload string\nbase64-encoded license payload\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-sr --support-request\ncreate a support request and exit\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-h --help\nreturns help for BreathGSLB\n\n")
		fmt.Fprint(flag.CommandLine.Output(), "-a --about\nreturns a detailed about page\n")
	}
	flag.Parse()

	if showHelp {
		flag.Usage()
		return
	}
	if showAbout {
		fmt.Print(aboutText())
		return
	}

	if licensePayload == "" {
		if b, err := os.ReadFile("/etc/breathgslb/license.payload"); err == nil {
			licensePayload = strings.TrimSpace(string(b))
		} else {
			log.Fatalf("license payload required")
		}
	}
	licensePayloadBytes, err := base64.StdEncoding.DecodeString(licensePayload)
	if err != nil {
		log.Fatalf("decode license payload: %v", err)
	}

	if activateKey != "" {
		if err := validateLicense(strings.TrimSpace(activateKey), licensePayloadBytes); err != nil {
			log.Fatalf("activate license: %v", err)
		}
		printSupportStatus()
		fmt.Println("license activated")
		return
	}

	if b, err := os.ReadFile("/etc/breathgslb/license"); err != nil || validateLicense(strings.TrimSpace(string(b)), licensePayloadBytes) != nil {
		r := bufio.NewReader(os.Stdin)
		fmt.Print("Enter license key: ")
		key, err := r.ReadString('\n')
		if err != nil {
			log.Fatalf("read license key: %v", err)
		}
		if err := validateLicense(strings.TrimSpace(key), licensePayloadBytes); err != nil {
			log.Fatalf("activate license: %v", err)
		}
	}
	printSupportStatus()

	if supportReq {
		if !isSupportActive() {
			log.Fatalf("support request requires active support")
		}
		if err := supportRequest(); err != nil {
			log.Fatalf("support request: %v", err)
		}
		return
	}

	fmt.Printf("BreathGSLB - V%s %s Release\n", version, buildOS)

	_ = supervisor

	adminAPIToken = apiToken

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("read config: %v\nadd -h or --help to get help", err)
	}
	config.SetupDefaults(cfg)
	config.GenerateTSIGKeys(cfg)

	if adminAPIToken == "" && cfg.APIToken != "" {
		if b, err := os.ReadFile(cfg.APIToken); err == nil {
			adminAPIToken = strings.TrimSpace(string(b))
		} else {
			adminAPIToken = cfg.APIToken
		}
	}
	if apiListen == "" && cfg.API {
		if cfg.APIListen > 0 {
			apiListen = ":" + strconv.Itoa(cfg.APIListen)
		}
		if cfg.APICert != "" {
			apiCert = cfg.APICert
		}
		if cfg.APIKey != "" {
			apiKey = cfg.APIKey
		}
	}

	w := logging.Setup(cfg)
	rand.Seed(time.Now().UnixNano())

	rt := &router{}
	rt.edns.Store(uint32(cfg.EDNSBuf))

	gr := newGeoResolver(cfg.GeoIP)
	sup = newSupervisor()
	mux, auths := buildMux(cfg, gr, sup, nil)
	rt.inner.Store(mux)

	current.mu.Lock()
	current.cfg = cfg
	current.rt = rt
	current.logW = w
	current.auths = auths
	current.geo = gr
	current.mu.Unlock()

	go sampleMemStats()
	dnsserver.StartListeners(rt, cfg, cfg.MaxWorkers)

	if debugPprof {
		go func() {
			log.Printf("pprof listening on %s", "localhost:6060")
			if err := http.ListenAndServe("localhost:6060", nil); err != nil {
				log.Printf("pprof: %v", err)
			}
		}()
	}

	if apiListen != "" && apiCert != "" && apiKey != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", healthHandler)
		mux.HandleFunc("/stats", statsHandler)
		mux.HandleFunc("/openapi.yaml", openapiHandler)
		mux.HandleFunc("/swagger/", swaggerHandler)
		serve := func(addr string) {
			log.Printf("admin https listening on %s", addr)
			if err := http.ListenAndServeTLS(addr, apiCert, apiKey, mux); err != nil {
				log.Printf("admin https: %v", err)
			}
		}
		addrs := []string{apiListen}
		if cfg.API && cfg.APIListen > 0 && len(cfg.APIInterface) > 0 && apiListen == ":"+strconv.Itoa(cfg.APIListen) {
			addrs = apiAddrs(cfg.APIInterface, cfg.APIListen)
		}
		for _, a := range addrs {
			go serve(a)
		}
	}

	handleSignals(cfgPath)
}

// generateTSIGKeys populates missing TSIG secrets and optionally writes them to disk.
func rrDiff(old, new []dns.RR) (del, add []dns.RR) {
	o := map[string]dns.RR{}
	for _, r := range old {
		o[r.String()] = r
	}
	n := map[string]dns.RR{}
	for _, r := range new {
		n[r.String()] = r
	}
	for k, r := range o {
		if _, ok := n[k]; !ok {
			del = append(del, r)
		}
	}
	for k, r := range n {
		if _, ok := o[k]; !ok {
			add = append(add, r)
		}
	}
	sort.Slice(del, func(i, j int) bool { return del[i].String() < del[j].String() })
	sort.Slice(add, func(i, j int) bool { return add[i].String() < add[j].String() })
	return
}

func buildMux(cfg *Config, gr *geoResolver, sup *supervisor, prev map[string]*authority) (dns.Handler, map[string]*authority) {
	mux := dns.NewServeMux()
	auths := make(map[string]*authority)
	for _, z := range cfg.Zones {
		zname := ensureDot(z.Name)
		ctx, cancel := context.WithCancel(context.Background())
		st := &state{cooldown: time.Duration(cfg.CooldownSec) * time.Second}
		auth := &authority{cfg: cfg, zone: z, state: st, ctx: ctx, cancel: cancel, geo: gr}
		if strings.ToLower(z.Serve) == "secondary" {
			auth.serial = 0
			auth.zidx = nil
		} else {
			auth.serial = nextSerial(zname)
			auth.zidx = buildIndex(z)
		}
		// DNSSEC keys & index
		auth.keys = loadDNSSEC(z)
		// parse local CIDRs once
		auth.cidrInit()

		if prev != nil {
			if old := prev[zname]; old != nil {
				del, add := rrDiff(old.axfrRecords(), auth.axfrRecords())
				if len(del) > 0 || len(add) > 0 {
					auth.ixfr = &ixfrDelta{old: old.soa().(*dns.SOA), del: del, new: auth.soa().(*dns.SOA), add: add}
				}
			}
		}

		mux.HandleFunc(zname, auth.handle)
		auths[zname] = auth
		if strings.ToLower(z.Serve) == "secondary" && len(z.Masters) > 0 {
			if sup != nil {
				sup.watch(ctx, zname+" fetchLoop", auth.fetchLoop)
			} else {
				go auth.fetchLoop()
			}
			log.Printf("serving secondary zone %s", zname)
		} else {
			if sup != nil {
				sup.watch(ctx, zname+" healthLoop", auth.healthLoop)
				sup.watch(ctx, zname+" purgeLoop", auth.purgeLoop)
			} else {
				go auth.healthLoop()
				go auth.purgeLoop()
			}
			log.Printf("serving zone %s", zname)
		}
	}
	return mux, auths
}

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if adminAPIToken == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	tok := strings.TrimPrefix(auth, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(tok), []byte(adminAPIToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func runtimeData(status bool) map[string]interface{} {
	statsMu.RLock()
	var mem runtime.MemStats
	if n := len(memStatsRecent); n > 0 {
		mem = memStatsRecent[n-1]
	}
	ms := make([]runtime.MemStats, len(memStatsRecent))
	copy(ms, memStatsRecent)
	lats := make([]float64, len(latencyRecent))
	for i, d := range latencyRecent {
		lats[i] = float64(d) / float64(time.Millisecond)
	}
	statsMu.RUnlock()

	vars := map[string]string{}
	expvar.Do(func(kv expvar.KeyValue) {
		vars[kv.Key] = kv.Value.String()
	})
	res := map[string]interface{}{
		"goroutines":      runtime.NumGoroutine(),
		"cgo_calls":       runtime.NumCgoCall(),
		"num_cpu":         runtime.NumCPU(),
		"memstats":        mem,
		"memstats_recent": ms,
		"latency_ms":      lats,
		"expvar":          vars,
		"uptime":          time.Since(startTime).Seconds(),
	}
	if sup != nil {
		res["supervisor"] = sup.snapshot()
	}
	if status {
		res["status"] = "ok"
	}
	return res
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(runtimeData(false))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(runtimeData(true))
}

func openapiHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(doc.OpenAPIYAML)
}

func swaggerHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(doc.SwaggerHTML)
}

type udpResponseWriter struct {
	conn    *net.UDPConn
	session *dns.SessionUDP
}

func (w *udpResponseWriter) LocalAddr() net.Addr                   { return w.conn.LocalAddr() }
func (w *udpResponseWriter) RemoteAddr() net.Addr                  { return w.session.RemoteAddr() }
func (w *udpResponseWriter) Close() error                          { return nil }
func (w *udpResponseWriter) TsigStatus() error                     { return nil }
func (w *udpResponseWriter) TsigTimersOnly(bool)                   {}
func (w *udpResponseWriter) Hijack()                               {}
func (w *udpResponseWriter) ConnectionState() *tls.ConnectionState { return nil }
func (w *udpResponseWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = dns.WriteToSessionUDP(w.conn, b, w.session)
	return err
}
func (w *udpResponseWriter) Write(b []byte) (int, error) {
	return dns.WriteToSessionUDP(w.conn, b, w.session)
}

func reload(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	config.SetupDefaults(cfg)
	config.GenerateTSIGKeys(cfg)

	newGeo := newGeoResolver(cfg.GeoIP)

	current.mu.Lock()
	prev := current.auths
	oldGeo := current.geo
	current.mu.Unlock()

	mux, auths := buildMux(cfg, newGeo, sup, prev)

	current.mu.Lock()
	current.rt.inner.Store(mux)
	current.rt.edns.Store(uint32(cfg.EDNSBuf))
	current.cfg = cfg
	current.auths = auths
	current.geo = newGeo
	current.mu.Unlock()

	for _, a := range prev {
		a.cancel()
	}
	current.mu.Lock()
	if current.logW != nil {
		_ = current.logW.Close()
	}
	current.logW = logging.Setup(cfg)
	current.cfg.LogFile = cfg.LogFile
	current.cfg.LogSyslog = cfg.LogSyslog
	current.mu.Unlock()
	if oldGeo != nil {
		oldGeo.Close()
	}
	return nil
}

func shutdown() {
	current.mu.Lock()
	defer current.mu.Unlock()
	for _, a := range current.auths {
		a.cancel()
	}
	if current.logW != nil {
		_ = current.logW.Close()
	}
	if current.geo != nil {
		current.geo.Close()
	}
}

// ---- request handling ----

func (a *authority) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if o := r.IsEdns0(); o != nil {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(o.UDPSize())
		if o.Do() {
			opt.SetDo()
		}
		for _, e := range o.Option {
			if c, ok := e.(*dns.EDNS0_COOKIE); ok {
				cc := *c
				opt.Option = append(opt.Option, &cc)
			}
		}
		m.Extra = append(m.Extra, opt)
	}
	m.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(ensureDot(q.Name))
	zone := ensureDot(a.zone.Name)
	z := strings.ToLower(zone)

	if a.cfg.LogQueries {
		log.Printf("query %s %s", name, dns.TypeToString[q.Qtype])
	}

	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		if name != z {
			m.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		if !a.xfrAllowed(w, r) {
			m.SetRcode(r, dns.RcodeRefused)
			if ts := r.IsTsig(); ts != nil {
				m.SetTsig(ts.Hdr.Name, ts.Algorithm, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
			return
		}
		a.xfr(w, r, q.Qtype == dns.TypeIXFR)
		return
	}

	if strings.ToLower(a.zone.Serve) == "secondary" {
		a.mu.RLock()
		if q.Qtype == dns.TypeSOA && name == z {
			if a.soaRR != nil {
				rr := *a.soaRR
				m.Answer = append(m.Answer, &rr)
			}
		} else {
			for _, rr := range a.records[name] {
				if q.Qtype == dns.TypeANY || rr.Header().Rrtype == q.Qtype {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if len(m.Answer) == 0 {
			for _, rr := range a.records[z] {
				if rr.Header().Rrtype == dns.TypeNS {
					m.Ns = append(m.Ns, rr)
				}
			}
			if a.soaRR != nil {
				rr := *a.soaRR
				m.Ns = append(m.Ns, &rr)
			}
		}
		a.mu.RUnlock()
		_ = w.WriteMsg(m)
		return
	}

	if name == z && q.Qtype == dns.TypeSOA {
		m.Answer = append(m.Answer, a.soa())
		if wantDNSSEC(r) && a.keys != nil && a.keys.enabled {
			m.Answer = a.signAll(m.Answer)
		}
		_ = w.WriteMsg(m)
		return
	}

	// Basic apex handling for SOA/NS/DNSKEY
	if name == z {
		switch q.Qtype {
		case dns.TypeNS:
			for _, ns := range a.zone.NS {
				m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(zone, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
			}
		case dns.TypeDNSKEY:
			if a.keys != nil && a.keys.enabled {
				for _, k := range a.dnskeyRRSet() {
					m.Answer = append(m.Answer, k)
				}
				if wantDNSSEC(r) {
					m.Answer = a.signAll(m.Answer)
				}
			}
		}
	}

	// client identity (ECS or source)
	cIP := clientIP(w, r)

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, a.addrA(name, cIP, r)...)
	case dns.TypeAAAA:
		m.Answer = append(m.Answer, a.addrAAAA(name, cIP, r)...)
	case dns.TypeTXT:
		m.Answer = append(m.Answer, a.txtFor(name)...)
	case dns.TypeMX:
		m.Answer = append(m.Answer, a.mxFor(name)...)
	case dns.TypeCAA:
		m.Answer = append(m.Answer, a.caaFor(name)...)
	case dns.TypeRP:
		if rr := a.rpFor(name); rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeSSHFP:
		m.Answer = append(m.Answer, a.sshfpFor(name)...)
	case dns.TypeSRV:
		m.Answer = append(m.Answer, a.srvFor(name)...)
	case dns.TypeNAPTR:
		m.Answer = append(m.Answer, a.naptrFor(name)...)
	}

	if len(m.Answer) == 0 {
		for _, ns := range a.zone.NS {
			m.Ns = append(m.Ns, &dns.NS{Hdr: hdr(zone, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
		}
		m.Ns = append(m.Ns, a.soa())
		missing := a.zidx != nil && !a.zidx.hasName(name)
		if missing {
			m.SetRcode(r, dns.RcodeNameError)
		}
		if wantDNSSEC(r) && a.keys != nil && a.keys.enabled && a.zidx != nil {
			if missing {
				closest := a.zidx.closestEncloser(name)
				nsecMap := map[string]*dns.NSEC{}
				var order []string
				if n := a.makeNSEC(a.zidx.prevName(name)); n != nil {
					ns := n.(*dns.NSEC)
					key := strings.ToLower(ns.Hdr.Name) + "|" + strings.ToLower(ns.NextDomain)
					if _, ok := nsecMap[key]; !ok {
						nsecMap[key] = ns
						order = append(order, key)
					}
				}
				if closest != "" {
					if n := a.makeNSEC(a.zidx.prevName("*." + closest)); n != nil {
						ns := n.(*dns.NSEC)
						key := strings.ToLower(ns.Hdr.Name) + "|" + strings.ToLower(ns.NextDomain)
						if _, ok := nsecMap[key]; !ok {
							nsecMap[key] = ns
							order = append(order, key)
						}
					}
				}
				for _, k := range order {
					m.Ns = append(m.Ns, nsecMap[k])
				}
			} else {
				if nsec := a.makeNSEC(name); nsec != nil {
					m.Ns = append(m.Ns, nsec)
				}
			}
		}
	}

	if wantDNSSEC(r) && a.keys != nil && a.keys.enabled {
		m.Answer = a.signAll(m.Answer)
		m.Ns = a.signAll(m.Ns)
	}
	_ = w.WriteMsg(m)
}

func (a *authority) xfrAllowed(w dns.ResponseWriter, r *dns.Msg) bool {
	if a.zone.TSIG == nil {
		return true
	}
	ts := r.IsTsig()
	if ts == nil || w.TsigStatus() != nil {
		if a.zone.TSIG.AllowUnsigned {
			return true
		}
		return false
	}
	ip := clientIP(w, r)
	keyName := ensureDot(ts.Hdr.Name)
	for _, k := range a.zone.TSIG.Keys {
		if ensureDot(k.Name) != keyName {
			continue
		}
		if len(k.AllowXFRFrom) == 0 {
			return true
		}
		for _, allow := range k.AllowXFRFrom {
			if strings.Contains(allow, "/") {
				if _, n, err := net.ParseCIDR(allow); err == nil && n.Contains(ip) {
					return true
				}
			} else if ip.Equal(net.ParseIP(allow)) {
				return true
			}
		}
		return false
	}
	return false
}

func (a *authority) xfr(w dns.ResponseWriter, r *dns.Msg, ixfr bool) {
	if !a.xfrAllowed(w, r) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		if ts := r.IsTsig(); ts != nil {
			m.SetTsig(ts.Hdr.Name, ts.Algorithm, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(m)
		_ = w.Close()
		return
	}
	tr := new(dns.Transfer)
	ch := make(chan *dns.Envelope)
	go func() {
		soa := a.soa()
		if ixfr {
			if len(r.Ns) > 0 {
				if rr, ok := r.Ns[0].(*dns.SOA); ok {
					if rr.Serial >= a.serial {
						ch <- &dns.Envelope{RR: []dns.RR{soa}}
						close(ch)
						return
					}
					if a.ixfr != nil && rr.Serial == a.ixfr.old.Serial {
						rrset := append([]dns.RR{a.ixfr.old}, a.ixfr.del...)
						rrset = append(rrset, a.ixfr.new)
						rrset = append(rrset, a.ixfr.add...)
						ch <- &dns.Envelope{RR: rrset}
						close(ch)
						return
					}
					log.Printf("ixfr diff unavailable for %s from serial %d; sending AXFR", a.zone.Name, rr.Serial)
				}
			}
		}
		records := a.axfrRecords()
		ch <- &dns.Envelope{RR: []dns.RR{soa}}
		for len(records) > 0 {
			end := 500
			if end > len(records) {
				end = len(records)
			}
			ch <- &dns.Envelope{RR: records[:end]}
			records = records[end:]
		}
		ch <- &dns.Envelope{RR: []dns.RR{soa}}
		close(ch)
	}()
	if err := tr.Out(w, r, ch); err != nil {
		log.Printf("xfr for %s failed: %v", a.zone.Name, err)
	}
	_ = w.Close()
}

func (a *authority) axfrRecords() []dns.RR {
	if strings.ToLower(a.zone.Serve) == "secondary" {
		a.mu.RLock()
		defer a.mu.RUnlock()
		out := make([]dns.RR, len(a.axfrRRs))
		copy(out, a.axfrRRs)
		return out
	}
	var rrs []dns.RR
	z := ensureDot(a.zone.Name)
	for _, ns := range a.zone.NS {
		rrs = append(rrs, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
	}
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AMaster))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AStandby))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AFallback))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AMasterPrivate))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AStandbyPrivate))...)
	rrs = append(rrs, a.buildA(config.IPsFrom(a.zone.AFallbackPrivate))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAMaster))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAStandby))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAFallback))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAMasterPrivate))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAStandbyPrivate))...)
	rrs = append(rrs, a.buildAAAA(config.IPsFrom(a.zone.AAAAFallbackPrivate))...)
	for _, t := range a.zone.TXT {
		name := ownerName(a.zone.Name, t.Name)
		ttl := t.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		if len(t.Text) > 0 {
			rrs = append(rrs, &dns.TXT{Hdr: hdr(name, dns.TypeTXT, ttl), Txt: t.Text})
		}
	}
	for _, mx := range a.zone.MX {
		name := ownerName(a.zone.Name, mx.Name)
		ttl := mx.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.MX{Hdr: hdr(name, dns.TypeMX, ttl), Preference: mx.Preference, Mx: ensureDot(mx.Exchange)})
	}
	for _, c := range a.zone.CAA {
		name := ownerName(a.zone.Name, c.Name)
		ttl := c.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.CAA{Hdr: hdr(name, dns.TypeCAA, ttl), Flag: c.Flag, Tag: c.Tag, Value: c.Value})
	}
	if a.zone.RP != nil {
		name := ownerName(a.zone.Name, a.zone.RP.Name)
		ttl := a.zone.RP.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.RP{Hdr: hdr(name, dns.TypeRP, ttl), Mbox: ensureDot(a.zone.RP.Mbox), Txt: ensureDot(a.zone.RP.Txt)})
	}
	for _, s := range a.zone.SSHFP {
		name := ownerName(a.zone.Name, s.Name)
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SSHFP{Hdr: hdr(name, dns.TypeSSHFP, ttl), Algorithm: s.Algorithm, Type: s.Type, FingerPrint: s.Fingerprint})
	}
	for _, s := range a.zone.SRV {
		name := ownerName(a.zone.Name, s.Name)
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SRV{Hdr: hdr(name, dns.TypeSRV, ttl), Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: ensureDot(s.Target)})
	}
	for _, n := range a.zone.NAPTR {
		name := ownerName(a.zone.Name, n.Name)
		ttl := n.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.NAPTR{Hdr: hdr(name, dns.TypeNAPTR, ttl), Order: n.Order, Preference: n.Preference, Flags: n.Flags, Service: n.Services, Regexp: n.Regexp, Replacement: ensureDot(n.Replacement)})
	}
	out := rrs
	rrs = nil
	return out
}

func clientIP(w dns.ResponseWriter, r *dns.Msg) net.IP {
	// Prefer ECS if present
	if opt := r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*dns.EDNS0_SUBNET); ok {
				if s.Address != nil {
					return s.Address
				}
			}
		}
	}
	addr := w.RemoteAddr()
	ua, _ := net.ResolveUDPAddr("udp", addr.String())
	if ua != nil && ua.IP != nil {
		return ua.IP
	}
	ta, _ := net.ResolveTCPAddr("tcp", addr.String())
	if ta != nil {
		return ta.IP
	}
	return nil
}

// Address selection for a given owner name
func (a *authority) addrA(owner string, src net.IP, r *dns.Msg) []dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	zone := strings.ToLower(ensureDot(a.zone.Name))
	if strings.HasSuffix(owner, zone) {
		host := strings.TrimSuffix(owner, zone)
		host = strings.TrimSuffix(host, ".")
		if host != "" {
			if tgt, ok := a.zone.AliasHost[strings.ToLower(host)]; ok {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
				defer cancel()
				ips := aliasLookup(ctx, tgt)
				var addrs []string
				for _, ip := range ips {
					if ip.To4() != nil {
						addrs = append(addrs, ip.String())
					}
				}
				if len(addrs) > 0 {
					return a.persistRR(a.buildA(addrs), src, false)
				}
				return nil
			}
		}
	}
	if owner != zone {
		return nil
	}
	// local view first if enabled
	if strings.ToLower(a.zone.Serve) == "local" && src != nil {
		if rr := a.localAnswers(false /*v6*/, src); rr != nil {
			return a.persistRR(rr, src, false)
		}
	}
	// Geo answer overrides (per country/continent) if configured
	if src != nil {
		if rr := a.answersByGeo(owner, src, false); rr != nil {
			return a.persistRR(rr, src, false)
		}
	}
	// Geo steering (policy-only) if configured
	if src != nil {
		if tier := a.pickTierByGeo(src, false); tier != "" {
			return a.persistRR(a.publicFor(tier, false), src, false)
		}
	}
	// public flow: master -> standby -> fallback
	mV4, _, sV4, _ := a.state.snapshot()
	var addrs []string
	if mV4 && len(a.zone.AMaster) > 0 {
		addrs = config.IPsFrom(a.zone.AMaster)
	} else if sV4 && len(a.zone.AStandby) > 0 {
		addrs = config.IPsFrom(a.zone.AStandby)
	} else if len(a.zone.AFallback) > 0 {
		addrs = config.IPsFrom(a.zone.AFallback)
	} else if a.zone.Alias != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
		defer cancel()
		ips := aliasLookup(ctx, a.zone.Alias)
		for _, ip := range ips {
			if ip.To4() != nil {
				addrs = append(addrs, ip.String())
			}
		}
	}
	return a.persistRR(a.buildA(addrs), src, false)
}

func (a *authority) addrAAAA(owner string, src net.IP, r *dns.Msg) []dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	zone := strings.ToLower(ensureDot(a.zone.Name))
	if strings.HasSuffix(owner, zone) {
		host := strings.TrimSuffix(owner, zone)
		host = strings.TrimSuffix(host, ".")
		if host != "" {
			if tgt, ok := a.zone.AliasHost[strings.ToLower(host)]; ok {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
				defer cancel()
				ips := aliasLookup(ctx, tgt)
				var addrs []string
				for _, ip := range ips {
					if ip.To4() == nil {
						addrs = append(addrs, ip.String())
					}
				}
				if len(addrs) > 0 {
					return a.persistRR(a.buildAAAA(addrs), src, true)
				}
				return nil
			}
		}
	}
	if owner != zone {
		return nil
	}
	if strings.ToLower(a.zone.Serve) == "local" && src != nil {
		if rr := a.localAnswers(true /*v6*/, src); rr != nil {
			return a.persistRR(rr, src, true)
		}
	}
	// Geo answer overrides first
	if src != nil {
		if rr := a.answersByGeo(owner, src, true); rr != nil {
			return a.persistRR(rr, src, true)
		}
	}
	// Policy-only geo if any
	if src != nil {
		if tier := a.pickTierByGeo(src, true); tier != "" {
			return a.persistRR(a.publicFor(tier, true), src, true)
		}
	}
	_, mV6, _, sV6 := a.state.snapshot()
	var addrs []string
	if mV6 && len(a.zone.AAAAMaster) > 0 {
		addrs = config.IPsFrom(a.zone.AAAAMaster)
	} else if sV6 && len(a.zone.AAAAStandby) > 0 {
		addrs = config.IPsFrom(a.zone.AAAAStandby)
	} else if len(a.zone.AAAAFallback) > 0 {
		addrs = config.IPsFrom(a.zone.AAAAFallback)
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
	if len(addrs) == 0 && src != nil && src.To4() == nil && a.cfg.DNS64Prefix != "" {
		prefix := net.ParseIP(a.cfg.DNS64Prefix)
		if prefix != nil {
			var rrs []dns.RR
			for _, rr := range a.addrA(owner, src, r) {
				if aRec, ok := rr.(*dns.A); ok {
					v6 := make(net.IP, net.IPv6len)
					copy(v6[:12], prefix.To16()[:12])
					copy(v6[12:], aRec.A.To4())
					rrs = append(rrs, &dns.AAAA{Hdr: hdr(ensureDot(owner), dns.TypeAAAA, a.zone.TTLAnswer), AAAA: v6})
				}
			}
			if len(rrs) > 0 {
				return rrs
			}
		}
	}
	return a.persistRR(a.buildAAAA(addrs), src, true)
}

func pickAddr(addrs []string, mode string, ctr *atomic.Uint64) string {
	if len(addrs) == 0 {
		return ""
	}
	switch strings.ToLower(mode) {
	case "random":
		return addrs[rand.Intn(len(addrs))]
	case "wrr", "rr":
		fallthrough
	default:
		idx := ctr.Add(1) - 1
		return addrs[int(idx)%len(addrs)]
	}
}

func (a *authority) persistRR(rrs []dns.RR, src net.IP, ipv6 bool) []dns.RR {
	if src == nil {
		return rrs
	}
	enabled := a.cfg.PersistenceEnabled || a.zone.PersistenceEnabled
	if !enabled || len(rrs) <= 1 {
		return rrs
	}
	mode := a.cfg.PersistenceMode
	if a.zone.PersistenceMode != "" {
		mode = a.zone.PersistenceMode
	}
	ttl := time.Duration(a.zone.TTLAnswer) * time.Second
	key := src.String()
	now := time.Now()
	var store *sync.Map
	var ctr *atomic.Uint64
	var build func([]string) []dns.RR
	if ipv6 {
		store = &a.persistAAAA
		ctr = &a.rrAAAA
		build = a.buildAAAA
	} else {
		store = &a.persistA
		ctr = &a.rrA
		build = a.buildA
	}
	if val, ok := store.Load(key); ok {
		pv := val.(persistEntry)
		if now.Before(pv.exp) {
			return build([]string{pv.ip})
		}
		store.Delete(key)
	}
	addrs := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if ipv6 {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				addrs = append(addrs, aaaa.AAAA.String())
			}
		} else {
			if aRec, ok := rr.(*dns.A); ok {
				addrs = append(addrs, aRec.A.String())
			}
		}
	}
	if len(addrs) <= 1 {
		return rrs
	}
	ip := pickAddr(addrs, mode, ctr)
	if ip == "" {
		return rrs
	}
	store.Store(key, persistEntry{ip: ip, exp: now.Add(ttl)})
	return build([]string{ip})
}

func (a *authority) buildA(addrs []string) []dns.RR {
	var (
		rrs []dns.RR
		m   dns.Msg
	)
	for _, ip := range addrs {
		p := net.ParseIP(ip)
		if p == nil || p.To4() == nil {
			continue
		}
		rr := &dns.A{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeA, a.zone.TTLAnswer), A: p.To4()}
		candidate := append(rrs, rr)
		if a.cfg.MaxRecords > 0 && len(candidate) > a.cfg.MaxRecords {
			break
		}
		m.Answer = candidate
		if m.Len() > a.cfg.EDNSBuf {
			break
		}
		rrs = candidate
	}
	return rrs
}

func (a *authority) buildAAAA(addrs []string) []dns.RR {
	var (
		rrs []dns.RR
		m   dns.Msg
	)
	for _, ip := range addrs {
		p := net.ParseIP(ip)
		if p == nil || p.To4() != nil {
			continue
		}
		rr := &dns.AAAA{Hdr: hdr(ensureDot(a.zone.Name), dns.TypeAAAA, a.zone.TTLAnswer), AAAA: p}
		candidate := append(rrs, rr)
		if a.cfg.MaxRecords > 0 && len(candidate) > a.cfg.MaxRecords {
			break
		}
		m.Answer = candidate
		if m.Len() > a.cfg.EDNSBuf {
			break
		}
		rrs = candidate
	}
	return rrs
}

func (a *authority) fetchLoop() {
	var expire time.Time
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}
		if err := a.transferFromMasters(); err != nil {
			log.Printf("xfr fetch for %s failed: %v", a.zone.Name, err)
			retry := time.Duration(a.zone.Retry) * time.Second
			if retry <= 0 {
				retry = time.Minute
			}
			if !expire.IsZero() && time.Now().After(expire) {
				a.mu.Lock()
				a.records = nil
				a.axfrRRs = nil
				a.soaRR = nil
				a.mu.Unlock()
			}
			select {
			case <-time.After(retry):
			case <-a.ctx.Done():
				return
			}
		} else {
			expire = time.Now().Add(time.Duration(a.zone.Expire) * time.Second)
			refresh := time.Duration(a.zone.Refresh) * time.Second
			if refresh <= 0 {
				refresh = 5 * time.Minute
			}
			select {
			case <-time.After(refresh):
			case <-a.ctx.Done():
				return
			}
		}
	}
}

func (a *authority) transferFromMasters() error {
	var lastErr error
	for _, master := range a.zone.Masters {
		addr := master
		if !strings.Contains(addr, ":") || strings.HasSuffix(addr, "]") {
			addr = net.JoinHostPort(addr, "53")
		}
		tr := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(a.zone.Name)
		if a.zone.TSIG != nil && len(a.zone.TSIG.Keys) > 0 {
			k := a.zone.TSIG.Keys[0]
			name := ensureDot(k.Name)
			alg := k.Algorithm
			if alg == "" {
				alg = dns.HmacSHA256
			}
			tr.TsigSecret = map[string]string{name: k.Secret}
			m.SetTsig(name, alg, 300, time.Now().Unix())
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
		startSOA, ok := all[0].(*dns.SOA)
		if !ok {
			lastErr = fmt.Errorf("first record not SOA")
			continue
		}
		endSOA, ok := all[len(all)-1].(*dns.SOA)
		if !ok {
			lastErr = fmt.Errorf("last record not SOA")
			continue
		}
		records := all[1 : len(all)-1]
		recMap := make(map[string][]dns.RR)
		nsList := []string{}
		for _, rr := range records {
			name := strings.ToLower(ensureDot(rr.Header().Name))
			recMap[name] = append(recMap[name], rr)
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ensureDot(ns.Hdr.Name), ensureDot(a.zone.Name)) {
				nsList = append(nsList, ensureDot(ns.Ns))
			}
		}
		a.mu.Lock()
		a.records = recMap
		a.axfrRRs = records
		a.soaRR = endSOA
		a.serial = endSOA.Serial
		a.zone.NS = nsList
		a.zone.Refresh = startSOA.Refresh
		a.zone.Retry = startSOA.Retry
		a.zone.Expire = startSOA.Expire
		a.zone.Admin = startSOA.Mbox
		a.zone.TTLSOA = startSOA.Hdr.Ttl
		a.zone.Minttl = startSOA.Minttl
		a.zidx = buildIndexFromRRs(a.zone.Name, records)
		a.mu.Unlock()
		return nil
	}
	return lastErr
}

func (a *authority) purgeLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			a.persistA.Range(func(k, v any) bool {
				if now.After(v.(persistEntry).exp) {
					a.persistA.Delete(k)
				}
				return true
			})
			a.persistAAAA.Range(func(k, v any) bool {
				if now.After(v.(persistEntry).exp) {
					a.persistAAAA.Delete(k)
				}
				return true
			})
		case <-a.ctx.Done():
			return
		}
	}
}

// localAnswers decides per-tier private/public answers for local sources.
func (a *authority) localAnswers(ipv6 bool, src net.IP) []dns.RR {
	// tier order master -> standby -> fallback
	if a.isLocal("master", src) {
		// if isolated and allowed, serve private regardless of health
		if a.zone.PrivateAllowWhenIsolated || a.tierUp("master", ipv6) {
			if rr := a.privateFor("master", ipv6); rr != nil {
				return rr
			}
			return a.publicFor("master", ipv6)
		}
	}
	if a.isLocal("standby", src) {
		if a.zone.PrivateAllowWhenIsolated || a.tierUp("standby", ipv6) {
			if rr := a.privateFor("standby", ipv6); rr != nil {
				return rr
			}
			return a.publicFor("standby", ipv6)
		}
	}
	if a.isLocal("fallback", src) {
		if a.zone.PrivateAllowWhenIsolated || true { // fallback assumed available
			if rr := a.privateFor("fallback", ipv6); rr != nil {
				return rr
			}
			return a.publicFor("fallback", ipv6)
		}
	}
	return nil
}

func (a *authority) tierUp(tier string, ipv6 bool) bool {
	mV4, mV6, sV4, sV6 := a.state.snapshot()
	switch tier {
	case "master":
		if ipv6 {
			return mV6
		}
		return mV4
	case "standby":
		if ipv6 {
			return sV6
		}
		return sV4
	default:
		return true // fallback assumed available
	}
}

// setMasterUp marks the master tier's up state for both address families.
// It acquires the state's mutex; tests should call this helper instead of
// manipulating state.master directly.
func (a *authority) setMasterUp(v4, v6 bool) {
	a.state.mu.Lock()
	a.state.master.v4.up = v4
	a.state.master.v6.up = v6
	a.state.mu.Unlock()
}

func (a *authority) privateFor(tier string, ipv6 bool) []dns.RR {
	switch tier {
	case "master":
		if !ipv6 && len(a.zone.AMasterPrivate) > 0 {
			return a.buildA(config.IPsFrom(a.zone.AMasterPrivate))
		}
		if ipv6 && len(a.zone.AAAAMasterPrivate) > 0 {
			return a.buildAAAA(config.IPsFrom(a.zone.AAAAMasterPrivate))
		}
	case "standby":
		if !ipv6 && len(a.zone.AStandbyPrivate) > 0 {
			return a.buildA(config.IPsFrom(a.zone.AStandbyPrivate))
		}
		if ipv6 && len(a.zone.AAAAStandbyPrivate) > 0 {
			return a.buildAAAA(config.IPsFrom(a.zone.AAAAStandbyPrivate))
		}
	case "fallback":
		if !ipv6 && len(a.zone.AFallbackPrivate) > 0 {
			return a.buildA(config.IPsFrom(a.zone.AFallbackPrivate))
		}
		if ipv6 && len(a.zone.AAAAFallbackPrivate) > 0 {
			return a.buildAAAA(config.IPsFrom(a.zone.AAAAFallbackPrivate))
		}
	}
	return nil
}

func (a *authority) publicFor(tier string, ipv6 bool) []dns.RR {
	switch tier {
	case "master":
		if !ipv6 {
			return a.buildA(config.IPsFrom(a.zone.AMaster))
		}
		return a.buildAAAA(config.IPsFrom(a.zone.AAAAMaster))
	case "standby":
		if !ipv6 {
			return a.buildA(config.IPsFrom(a.zone.AStandby))
		}
		return a.buildAAAA(config.IPsFrom(a.zone.AAAAStandby))
	default:
		if !ipv6 {
			return a.buildA(config.IPsFrom(a.zone.AFallback))
		}
		return a.buildAAAA(config.IPsFrom(a.zone.AAAAFallback))
	}
}

func (a *authority) cidrInit() {
	parseAll := func(cidrs []string) []*net.IPNet {
		var out []*net.IPNet
		for _, s := range cidrs {
			_, n, err := net.ParseCIDR(strings.TrimSpace(s))
			if err == nil && n != nil {
				out = append(out, n)
			}
		}
		return out
	}
	// per-tier local ranges
	a.cidrs.master.rfc = parseAll(a.zone.RFCMaster)
	a.cidrs.master.ula = parseAll(a.zone.ULAMaster)
	a.cidrs.standby.rfc = parseAll(a.zone.RFCStandby)
	a.cidrs.standby.ula = parseAll(a.zone.ULAStandby)
	a.cidrs.fallback.rfc = parseAll(a.zone.RFCFallback)
	a.cidrs.fallback.ula = parseAll(a.zone.ULAFallback)

	// geo_answers CIDRs
	a.geoCIDR.country = map[string]parsedCIDRs{}
	a.geoCIDR.continent = map[string]parsedCIDRs{}
	if a.zone.GeoAnswers != nil {
		for k, set := range a.zone.GeoAnswers.Country {
			kk := strings.ToUpper(strings.TrimSpace(k))
			a.geoCIDR.country[kk] = parsedCIDRs{rfc: parseAll(set.RFC), ula: parseAll(set.ULA)}
		}
		for k, set := range a.zone.GeoAnswers.Continent {
			kk := strings.ToUpper(strings.TrimSpace(k))
			a.geoCIDR.continent[kk] = parsedCIDRs{rfc: parseAll(set.RFC), ula: parseAll(set.ULA)}
		}
	}
}

func (a *authority) isLocal(tier string, ip net.IP) bool {
	inAny := func(nets []*net.IPNet) bool {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	switch tier {
	case "master":
		return inAny(a.cidrs.master.rfc) || inAny(a.cidrs.master.ula)
	case "standby":
		return inAny(a.cidrs.standby.rfc) || inAny(a.cidrs.standby.ula)
	default:
		return inAny(a.cidrs.fallback.rfc) || inAny(a.cidrs.fallback.ula)
	}
}

// Geo steering helpers
func (a *authority) pickTierByGeo(src net.IP, ipv6 bool) string {
	if a.geo == nil || a.zone.Geo == nil || src == nil {
		return ""
	}
	cc, cont, ok := a.geo.lookup(src)
	if !ok {
		return ""
	}
	// Check in order: master -> standby -> fallback, but only if policy allows
	check := func(tier string, famV6 bool) bool {
		if !a.policyAllows(tier, cc, cont) {
			return false
		}
		// also require health for master/standby
		if tier == "fallback" {
			return true
		}
		return a.tierUp(tier, famV6)
	}
	if check("master", ipv6) {
		return "master"
	}
	if check("standby", ipv6) {
		return "standby"
	}
	if a.policyAllows("fallback", cc, cont) {
		return "fallback"
	}
	return ""
}

func (a *authority) policyAllows(tier string, country, continent string) bool {
	g := a.zone.Geo
	if g == nil {
		return false
	}
	var tp GeoTierPolicy
	switch tier {
	case "master":
		tp = g.Master
	case "standby":
		tp = g.Standby
	default:
		tp = g.Fallback
	}
	if tp.AllowAll {
		return true
	}
	country = strings.ToUpper(strings.TrimSpace(country))
	continent = strings.ToUpper(strings.TrimSpace(continent))
	contains := func(list []string, v string) bool {
		for _, x := range list {
			if strings.ToUpper(strings.TrimSpace(x)) == v {
				return true
			}
		}
		return false
	}
	if len(tp.AllowCountries) > 0 && contains(tp.AllowCountries, country) {
		return true
	}
	if len(tp.AllowContinents) > 0 && contains(tp.AllowContinents, continent) {
		return true
	}
	return false
}

// Geo answer overrides
func (a *authority) answersByGeo(owner string, src net.IP, ipv6 bool) []dns.RR {
	if a.geo == nil || a.zone.GeoAnswers == nil || src == nil {
		return nil
	}
	cc, cont, ok := a.geo.lookup(src)
	if !ok {
		return nil
	}
	cc = strings.ToUpper(cc)
	cont = strings.ToUpper(cont)
	// Country has priority over continent
	if s, ok := a.zone.GeoAnswers.Country[cc]; ok {
		if a.isLocalGeo(cc, true, src) { // true => country
			if ipv6 && len(s.AAAAPrivate) > 0 {
				return a.buildAAAA(s.AAAAPrivate)
			}
			if !ipv6 && len(s.APrivate) > 0 {
				return a.buildA(s.APrivate)
			}
		}
		if ipv6 && len(s.AAAA) > 0 {
			return a.buildAAAA(s.AAAA)
		}
		if !ipv6 && len(s.A) > 0 {
			return a.buildA(s.A)
		}
	}
	if s, ok := a.zone.GeoAnswers.Continent[cont]; ok {
		if a.isLocalGeo(cont, false, src) { // false => continent
			if ipv6 && len(s.AAAAPrivate) > 0 {
				return a.buildAAAA(s.AAAAPrivate)
			}
			if !ipv6 && len(s.APrivate) > 0 {
				return a.buildA(s.APrivate)
			}
		}
		if ipv6 && len(s.AAAA) > 0 {
			return a.buildAAAA(s.AAAA)
		}
		if !ipv6 && len(s.A) > 0 {
			return a.buildA(s.A)
		}
	}
	return nil
}

func inAnyCIDR(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *authority) isLocalGeo(key string, isCountry bool, ip net.IP) bool {
	if isCountry {
		p, ok := a.geoCIDR.country[key]
		if !ok {
			return false
		}
		return inAnyCIDR(ip, p.rfc) || inAnyCIDR(ip, p.ula)
	}
	p, ok := a.geoCIDR.continent[key]
	if !ok {
		return false
	}
	return inAnyCIDR(ip, p.rfc) || inAnyCIDR(ip, p.ula)
}

func (a *authority) soa() dns.RR {
	if strings.ToLower(a.zone.Serve) == "secondary" {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if a.soaRR != nil {
			rr := *a.soaRR
			return &rr
		}
	}
	z := ensureDot(a.zone.Name)
	nsPrimary := ensureDot(a.zone.NS[0])
	return &dns.SOA{Hdr: hdr(z, dns.TypeSOA, a.zone.TTLSOA), Ns: nsPrimary, Mbox: ensureDot(a.zone.Admin), Serial: a.serial, Refresh: a.zone.Refresh, Retry: a.zone.Retry, Expire: a.zone.Expire, Minttl: a.zone.Minttl}
}

func hdr(name string, t uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
}

func ensureDot(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}
func ownerName(apex, s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == "@" {
		return ensureDot(apex)
	}
	return ensureDot(s)
}

// Shared/static helpers
func (a *authority) txtFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, t := range a.zone.TXT {
		name := ownerName(a.zone.Name, t.Name)
		if name != owner {
			continue
		}
		ttl := t.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		if len(t.Text) > 0 {
			rrs = append(rrs, &dns.TXT{Hdr: hdr(name, dns.TypeTXT, ttl), Txt: t.Text})
		}
	}
	return rrs
}

func (a *authority) mxFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, mx := range a.zone.MX {
		name := ownerName(a.zone.Name, mx.Name)
		if name != owner {
			continue
		}
		ttl := mx.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.MX{Hdr: hdr(name, dns.TypeMX, ttl), Preference: mx.Preference, Mx: ensureDot(mx.Exchange)})
	}
	return rrs
}

func (a *authority) caaFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, c := range a.zone.CAA {
		name := ownerName(a.zone.Name, c.Name)
		if name != owner {
			continue
		}
		ttl := c.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.CAA{Hdr: hdr(name, dns.TypeCAA, ttl), Flag: c.Flag, Tag: c.Tag, Value: c.Value})
	}
	return rrs
}

func (a *authority) rpFor(owner string) dns.RR {
	owner = ensureDot(owner)
	if a.zone.RP == nil {
		return nil
	}
	name := ownerName(a.zone.Name, a.zone.RP.Name)
	if name != owner {
		return nil
	}
	ttl := a.zone.RP.TTL
	if ttl == 0 {
		ttl = a.zone.TTLAnswer
	}
	return &dns.RP{Hdr: hdr(name, dns.TypeRP, ttl), Mbox: ensureDot(a.zone.RP.Mbox), Txt: ensureDot(a.zone.RP.Txt)}
}

func (a *authority) sshfpFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, s := range a.zone.SSHFP {
		name := ownerName(a.zone.Name, s.Name)
		if name != owner {
			continue
		}
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SSHFP{Hdr: hdr(name, dns.TypeSSHFP, ttl), Algorithm: s.Algorithm, Type: s.Type, FingerPrint: s.Fingerprint})
	}
	return rrs
}

func (a *authority) srvFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, s := range a.zone.SRV {
		name := ownerName(a.zone.Name, s.Name)
		if name != owner {
			continue
		}
		ttl := s.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.SRV{Hdr: hdr(name, dns.TypeSRV, ttl), Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: ensureDot(s.Target)})
	}
	return rrs
}

func (a *authority) naptrFor(owner string) []dns.RR {
	owner = ensureDot(owner)
	rrs := []dns.RR{}
	for _, n := range a.zone.NAPTR {
		name := ownerName(a.zone.Name, n.Name)
		if name != owner {
			continue
		}
		ttl := n.TTL
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		rrs = append(rrs, &dns.NAPTR{Hdr: hdr(name, dns.TypeNAPTR, ttl), Order: n.Order, Preference: n.Preference, Flags: n.Flags, Service: n.Services, Regexp: n.Regexp, Replacement: ensureDot(n.Replacement)})
	}
	return rrs
}

// ---- health loop ----

func (a *authority) healthLoop() {
	base := time.Duration(a.cfg.IntervalSec) * time.Second
	if base <= 0 {
		base = 5 * time.Second
	}
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
			a.checkOnce()
			jitter := time.Duration(0)
			if a.cfg.JitterMs > 0 {
				jitter = time.Duration(rand.Intn(a.cfg.JitterMs+1)) * time.Millisecond
			}
			time.Sleep(base + jitter)
		}
	}
}

func (a *authority) checkOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.TimeoutSec)*time.Second)
	defer cancel()

	hc := healthcheck.Effective(a.zone.Name, a.zone.Health)

	// master v4

	m4 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AMaster), hc)
	a.state.set("master", false, m4, a.cfg.Rise, a.cfg.Fall)
	// master v6
	m6 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AAAAMaster), hc)
	a.state.set("master", true, m6, a.cfg.Rise, a.cfg.Fall)
	// standby v4
	s4 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AStandby), hc)
	a.state.set("standby", false, s4, a.cfg.Rise, a.cfg.Fall)
	// standby v6
	s6 := healthcheck.ProbeAny(ctx, config.IPsFrom(a.zone.AAAAStandby), hc)
	a.state.set("standby", true, s6, a.cfg.Rise, a.cfg.Fall)
}

func aliasLookup(ctx context.Context, target string) []net.IP {
	target = strings.TrimSuffix(target, ".")
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return nil
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips
}

// ---- DNSSEC helpers ----

func wantDNSSEC(r *dns.Msg) bool {
	if o := r.IsEdns0(); o != nil {
		return o.Do()
	}
	return false
}

func loadDNSSEC(z Zone) *dnssecKeys {
	if z.DNSSEC == nil || z.DNSSEC.Mode == "" || z.DNSSEC.Mode == DNSSECModeOff {
		return &dnssecKeys{enabled: false}
	}
	baseZ := strings.TrimSuffix(ensureDot(z.Name), ".")
	switch z.DNSSEC.Mode {
	case DNSSECModeManual:
		zsk := z.DNSSEC.ZSKFile
		ksk := z.DNSSEC.KSKFile
		if zsk == "" {
			return &dnssecKeys{enabled: false}
		}
		if ksk == "" {
			ksk = zsk
		}
		if zsk == ksk {
			zk, zpriv, err := parseBindKeyPair(baseZ, zsk)
			if err != nil {
				log.Printf("dnssec key load failed: %v", err)
				return &dnssecKeys{enabled: false}
			}
			return &dnssecKeys{enabled: true, zsk: zk, zskPriv: zpriv, ksk: zk, kskPriv: zpriv}
		}
		zk, zpriv, err := parseBindKeyPair(baseZ, zsk)
		if err != nil {
			log.Printf("dnssec zsk load failed: %v", err)
			return &dnssecKeys{enabled: false}
		}
		kk, kpriv, err := parseBindKeyPair(baseZ, ksk)
		if err != nil {
			log.Printf("dnssec ksk load failed: %v", err)
			return &dnssecKeys{enabled: false}
		}
		return &dnssecKeys{enabled: true, zsk: zk, zskPriv: zpriv, ksk: kk, kskPriv: kpriv}
	case DNSSECModeGenerated:
		zskPath := z.DNSSEC.ZSKFile
		kskPath := z.DNSSEC.KSKFile
		if zskPath == "" {
			zskPath = filepath.Join(".", baseZ)
		}
		if kskPath == "" {
			kskPath = zskPath
		}
		if zskPath == kskPath {
			zskPath += ".zsk"
			kskPath += ".ksk"
		}
		zk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ensureDot(z.Name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 256, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
		zp, err := zk.Generate(256)
		if err != nil {
			log.Printf("dnssec zsk generate failed: %v", err)
			return &dnssecKeys{enabled: false}
		}
		kk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ensureDot(z.Name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
		kp, err := kk.Generate(256)
		if err != nil {
			log.Printf("dnssec ksk generate failed: %v", err)
			return &dnssecKeys{enabled: false}
		}
		if err := writeBindKeyPair(zskPath, zk, zp); err != nil {
			log.Printf("dnssec zsk persist failed: %v", err)
		}
		if err := writeBindKeyPair(kskPath, kk, kp); err != nil {
			log.Printf("dnssec ksk persist failed: %v", err)
		}
		zs, ok := zp.(crypto.Signer)
		if !ok {
			log.Printf("dnssec zsk priv not signer")
			return &dnssecKeys{enabled: false}
		}
		ks, ok := kp.(crypto.Signer)
		if !ok {
			log.Printf("dnssec ksk priv not signer")
			return &dnssecKeys{enabled: false}
		}
		return &dnssecKeys{enabled: true, zsk: zk, zskPriv: zs, ksk: kk, kskPriv: ks}
	default:
		log.Printf("dnssec mode %q not supported", z.DNSSEC.Mode)
		return &dnssecKeys{enabled: false}
	}
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
	if err != nil {
		return nil, nil, err
	}
	rr, err := dns.NewRR(string(pubData))
	if err != nil {
		return nil, nil, err
	}
	dk, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, nil, fmt.Errorf("not a DNSKEY in %s", pubPath)
	}
	f, err := os.Open(privPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	privAny, err := dk.ReadPrivateKey(f, privPath)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := privAny.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key %s does not implement crypto.Signer", privPath)
	}
	return dk, signer, nil
}

func writeBindKeyPair(prefix string, key *dns.DNSKEY, priv crypto.PrivateKey) error {
	pubPath := prefix
	privPath := prefix
	if !strings.HasSuffix(pubPath, ".key") {
		pubPath += ".key"
	}
	if !strings.HasSuffix(privPath, ".private") {
		privPath += ".private"
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, []byte(key.String()+"\n"), 0o644); err != nil {
		return err
	}
	privStr := key.PrivateKeyString(priv)
	if err := os.WriteFile(privPath, []byte(privStr), 0o600); err != nil {
		return err
	}
	return nil
}

func (a *authority) dnskeyRRSet() []dns.RR {
	if a.keys == nil || !a.keys.enabled {
		return nil
	}
	var out []dns.RR
	if a.keys.zsk != nil {
		out = append(out, a.keys.zsk)
	}
	if a.keys.ksk != nil && a.keys.ksk != a.keys.zsk {
		out = append(out, a.keys.ksk)
	}
	for i := range out {
		out[i].Header().Name = ensureDot(a.zone.Name)
		out[i].Header().Ttl = a.zone.TTLAnswer
	}
	return out
}

// signAll walks over rrs and appends RRSIGs per RRset type/name (ZSK; DNSKEY uses KSK)
func (a *authority) signAll(in []dns.RR) []dns.RR {
	if a.keys == nil || !a.keys.enabled {
		return in
	}
	if len(in) == 0 {
		return in
	}
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
		key := a.keys.zsk
		priv := a.keys.zskPriv
		if len(g) > 0 && g[0].Header().Rrtype == dns.TypeDNSKEY {
			key = a.keys.ksk
			priv = a.keys.kskPriv
		}
		if key == nil || priv == nil {
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
	now := time.Now().UTC()
	incep := uint32(now.Add(-5 * time.Minute).Unix())
	exp := uint32(now.Add(6 * time.Hour).Unix())
	return &dns.RRSIG{Hdr: hdr(name, dns.TypeRRSIG, ttl), TypeCovered: rrset[0].Header().Rrtype, Algorithm: key.Algorithm, Labels: labels, OrigTtl: ttl, Expiration: exp, Inception: incep, KeyTag: key.KeyTag(), SignerName: ensureDot(a.zone.Name)}
}

// makeNSEC builds an NSEC record for the provided owner. The owner must exist
// in the zone index.
func (a *authority) makeNSEC(owner string) dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	if a.zidx == nil || !a.zidx.hasName(owner) {
		return nil
	}
	idx := a.zidx
	next := idx.nextName(owner)

	typesHere := idx.typeBitmap(owner)
	zname := strings.ToLower(ensureDot(a.zone.Name))
	bm := make([]uint16, 0, len(typesHere)+2)
	if owner == zname {
		bm = append(bm, typesHere...)
	} else {
		for _, t := range typesHere {
			if t == dns.TypeSOA || t == dns.TypeDNSKEY {
				continue
			}
			bm = append(bm, t)
		}
	}

	hasNSEC, hasRRSIG := false, false
	for _, t := range bm {
		if t == dns.TypeNSEC {
			hasNSEC = true
		}
		if t == dns.TypeRRSIG {
			hasRRSIG = true
		}
	}
	if !hasNSEC {
		bm = append(bm, dns.TypeNSEC)
	}
	if !hasRRSIG {
		bm = append(bm, dns.TypeRRSIG)
	}
	sort.Slice(bm, func(i, j int) bool { return bm[i] < bm[j] })

	return &dns.NSEC{Hdr: hdr(ensureDot(owner), dns.TypeNSEC, a.zone.TTLAnswer), NextDomain: ensureDot(next), TypeBitMap: bm}
}

// ---- zone index helpers ----
