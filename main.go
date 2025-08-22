package main

import (
	"context"
	"crypto"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
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
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"encoding/base64"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// HealthConfig holds per-zone health probe settings.
type HealthKind string

const (
	HKHTTP  HealthKind = "http"  // existing
	HKHTTP3 HealthKind = "http3" // new: HTTP/3 over QUIC
	HKTCP   HealthKind = "tcp"   // new: TCP connect (optionally TLS)
	HKUDP   HealthKind = "udp"   // new: UDP send/expect
	HKICMP  HealthKind = "icmp"  // new: ICMP/ICMPv6 echo
	HKRawIP HealthKind = "rawip" // new: raw IP protocol probe

)

type HealthConfig struct {
	Kind        HealthKind `yaml:"kind,omitempty"` // defaults "http"
	HostHeader  string     `yaml:"host_header,omitempty"`
	Path        string     `yaml:"path,omitempty"` // default "/health"
	SNI         string     `yaml:"sni,omitempty"`
	InsecureTLS bool       `yaml:"insecure_tls,omitempty"`
	Scheme      string     `yaml:"scheme,omitempty"` // http|https (http default https)
	Method      string     `yaml:"method,omitempty"` // GET|POST (default GET)
	Port        int        `yaml:"port,omitempty"`   // default 443 (http picks 80)
	Expect      string     `yaml:"expect,omitempty"` // substring expected in body for http/http3

	// TCP options
	TLSEnable  bool     `yaml:"tls_enable,omitempty"` // if Kind=tcp, do TLS ClientHello
	ALPN       string   `yaml:"alpn,omitempty"`       // e.g. "h2,http/1.1"
	ALPNProtos []string `yaml:"-"`                    // parsed ALPN protocols

	// UDP options
	UDPPayloadB64 string `yaml:"udp_payload_b64,omitempty"` // data to send
	UDPExpectRE   string `yaml:"udp_expect_re,omitempty"`   // regex on response (optional)

	// ICMP options
	ICMPPayloadB64 string `yaml:"icmp_payload_b64,omitempty"` // optional extra payload

	// raw IP options
	Protocol int `yaml:"protocol,omitempty"` // IP protocol number
}

// ---- GeoIP config & policy ----

type GeoIPConfig struct {
	Enabled     bool   `yaml:"enabled"`       // enable GeoIP reader
	Database    string `yaml:"database"`      // path to GeoLite2-Country.mmdb
	PreferField string `yaml:"prefer_field"`  // "registered" | "country" (default registered)
	CacheTTLSec int    `yaml:"cache_ttl_sec"` // default 600
}

type GeoTierPolicy struct {
	AllowCountries  []string `yaml:"allow_countries,omitempty"`  // ISO 2-letter codes, e.g. GB, US
	AllowContinents []string `yaml:"allow_continents,omitempty"` // 2-letter codes, e.g. EU, NA
	AllowAll        bool     `yaml:"allow_all,omitempty"`        // if true, tier is eligible for any geo
}

type GeoPolicy struct {
	Master   GeoTierPolicy `yaml:"master,omitempty"`
	Standby  GeoTierPolicy `yaml:"standby,omitempty"`
	Fallback GeoTierPolicy `yaml:"fallback,omitempty"`
}

type GeoAnswerSet struct {
	A           []string `yaml:"a,omitempty"`
	AAAA        []string `yaml:"aaaa,omitempty"`
	APrivate    []string `yaml:"a_private,omitempty"`
	AAAAPrivate []string `yaml:"aaaa_private,omitempty"`
	RFC         []string `yaml:"rfc,omitempty"`
	ULA         []string `yaml:"ula,omitempty"`
}

type GeoAnswers struct {
	Country   map[string]GeoAnswerSet `yaml:"country,omitempty"`
	Continent map[string]GeoAnswerSet `yaml:"continent,omitempty"`
}

// ---- DNSSEC config ----

type DNSSECZoneConfig struct {
	Enable  bool   `yaml:"enable"`
	ZSKFile string `yaml:"zsk_keyfile,omitempty"` // BIND-style prefix without extension
	KSKFile string `yaml:"ksk_keyfile,omitempty"` // if empty, ZSKFile is used for both
}

// TSIGGlobalConfig holds global TSIG parameters.
type TSIGGlobalConfig struct {
	Path string `yaml:"path,omitempty"`
}

// TSIGKey describes a single TSIG key.
type TSIGKey struct {
	Name         string   `yaml:"name"`
	Algorithm    string   `yaml:"algorithm,omitempty"`
	Secret       string   `yaml:"secret,omitempty"`
	AllowXFRFrom []string `yaml:"allow_xfr_from,omitempty"`
}

// TSIGZoneConfig holds per-zone TSIG options.
type TSIGZoneConfig struct {
	DefaultAlgorithm string    `yaml:"default_algorithm,omitempty"`
	SeedEnv          string    `yaml:"seed_env,omitempty"`
	Epoch            int       `yaml:"epoch,omitempty"`
	Keys             []TSIGKey `yaml:"keys,omitempty"`
}

// Config is the top-level YAML.
type Config struct {
	Listen      string   `yaml:"listen"`
	ListenAddrs []string `yaml:"listen_addrs,omitempty"`
	Interfaces  []string `yaml:"interfaces,omitempty"`
	ReverseDir  string   `yaml:"reverse_dir,omitempty"`
	Zones       []Zone   `yaml:"zones"`

	TimeoutSec  int  `yaml:"timeout_sec"`
	IntervalSec int  `yaml:"interval_sec"`
	Rise        int  `yaml:"rise"`
	Fall        int  `yaml:"fall"`
	EDNSBuf     int  `yaml:"edns_buf"`
	MaxRecords  int  `yaml:"max_records,omitempty"`
	LogQueries  bool `yaml:"log_queries"`
	MaxWorkers  int  `yaml:"max_workers"`

	// Softening knobs
	JitterMs    int `yaml:"jitter_ms"`
	CooldownSec int `yaml:"cooldown_sec"`

	// DNS64 synthesis prefix (empty disables)
	DNS64Prefix string `yaml:"dns64_prefix,omitempty"`

	// Persistence options
	PersistenceEnabled bool   `yaml:"persistence_enabled,omitempty"`
	PersistenceMode    string `yaml:"persistence_mode,omitempty"`
	// Logging options
	LogFile   string `yaml:"log_file"`
	LogSyslog bool   `yaml:"log_syslog,omitempty"`

	// Global TSIG settings
	TSIG *TSIGGlobalConfig `yaml:"tsig,omitempty"`

	// Optional GeoIP steering
	GeoIP *GeoIPConfig `yaml:"geoip,omitempty"`
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
	Name     string `yaml:"name"`
	Priority uint16 `yaml:"priority"`
	Weight   uint16 `yaml:"weight"`
	Port     uint16 `yaml:"port"`
	Target   string `yaml:"target"`
	TTL      uint32 `yaml:"ttl,omitempty"`
}

type NAPTRRecord struct {
	Name        string `yaml:"name"`
	Order       uint16 `yaml:"order"`
	Preference  uint16 `yaml:"preference"`
	Flags       string `yaml:"flags"`
	Services    string `yaml:"services"`
	Regexp      string `yaml:"regexp"`
	Replacement string `yaml:"replacement"`
	TTL         uint32 `yaml:"ttl,omitempty"`
}

// Zone defines a single authoritative child zone served here.
type Zone struct {
	Name      string   `yaml:"name"`  // FQDN with trailing dot
	NS        []string `yaml:"ns"`    // FQDNs with trailing dots
	Admin     string   `yaml:"admin"` // hostmaster email as hostmaster.example.com.
	TTLSOA    uint32   `yaml:"ttl_soa"`
	TTLAnswer uint32   `yaml:"ttl_answer"`

	PersistenceEnabled bool   `yaml:"persistence_enabled,omitempty"`
	PersistenceMode    string `yaml:"persistence_mode,omitempty"`

	// View control
	Serve                    string `yaml:"serve,omitempty"` // "global" | "local" (default: global)
	PrivateAllowWhenIsolated bool   `yaml:"private_allow_when_isolated,omitempty"`

	// Tiered public answers
	AMaster      []IPAddr `yaml:"a_master,omitempty"`
	AAAAMaster   []IPAddr `yaml:"aaaa_master,omitempty"`
	AStandby     []IPAddr `yaml:"a_standby,omitempty"`
	AAAAStandby  []IPAddr `yaml:"aaaa_standby,omitempty"`
	AFallback    []IPAddr `yaml:"a_fallback,omitempty"`
	AAAAFallback []IPAddr `yaml:"aaaa_fallback,omitempty"`

	// Optional per-tier private answers (served only to local source ranges)
	AMasterPrivate      []IPAddr `yaml:"a_master_private,omitempty"`
	AAAAMasterPrivate   []IPAddr `yaml:"aaaa_master_private,omitempty"`
	AStandbyPrivate     []IPAddr `yaml:"a_standby_private,omitempty"`
	AAAAStandbyPrivate  []IPAddr `yaml:"aaaa_standby_private,omitempty"`
	AFallbackPrivate    []IPAddr `yaml:"a_fallback_private,omitempty"`
	AAAAFallbackPrivate []IPAddr `yaml:"aaaa_fallback_private,omitempty"`

	// Per-tier local source ranges (RFC1918 and ULA)
	RFCMaster   []string `yaml:"rfc_master,omitempty"`
	ULAMaster   []string `yaml:"ula_master,omitempty"`
	RFCStandby  []string `yaml:"rfc_standby,omitempty"`
	ULAStandby  []string `yaml:"ula_standby,omitempty"`
	RFCFallback []string `yaml:"rfc_fallback,omitempty"`
	ULAFallback []string `yaml:"ula_fallback,omitempty"`

	// Optional ALIAS-like target when no explicit A/AAAA (unchanged)
	Alias string `yaml:"alias,omitempty"`

	// Shared/static records
	TXT   []TXTRecord   `yaml:"txt,omitempty"`
	MX    []MXRecord    `yaml:"mx,omitempty"`
	CAA   []CAARecord   `yaml:"caa,omitempty"`
	RP    *RPRecord     `yaml:"rp,omitempty"`
	SSHFP []SSHFPRecord `yaml:"sshfp,omitempty"`
	SRV   []SRVRecord   `yaml:"srv,omitempty"`
	NAPTR []NAPTRRecord `yaml:"naptr,omitempty"`

	// Geo steering policy (optional)
	Geo *GeoPolicy `yaml:"geo,omitempty"`
	// Optional direct geo overrides (answers per country/continent)
	GeoAnswers *GeoAnswers `yaml:"geo_answers,omitempty"`

	Health *HealthConfig     `yaml:"health,omitempty"`
	DNSSEC *DNSSECZoneConfig `yaml:"dnssec,omitempty"`
	TSIG   *TSIGZoneConfig   `yaml:"tsig,omitempty"`
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

//go:embed doc/openapi.yaml
var openapiSpec []byte

//go:embed doc/swagger.html
var swaggerPage []byte

func main() {
	var cfgPath string
	var apiListen string
	var supervisor string
	var apiToken string
	var apiCert string
	var apiKey string
	var debugPprof bool

	flag.StringVar(&cfgPath, "config", "config.yaml", "path to YAML config")
	flag.StringVar(&apiListen, "api-listen", "", "HTTPS listen address for admin API")
	flag.StringVar(&supervisor, "supervisor", "", "supervisor notification target")
	flag.StringVar(&apiToken, "api-token", "", "admin API bearer token")
	flag.StringVar(&apiCert, "api-cert", "", "TLS certificate for admin API")
	flag.StringVar(&apiKey, "api-key", "", "TLS key for admin API")
	flag.BoolVar(&debugPprof, "debug-pprof", false, "enable pprof debug server on localhost:6060")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	_ = supervisor

	adminAPIToken = apiToken

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	setupDefaults(cfg)
	generateTSIGKeys(cfg)

	w := setupLogging(cfg)
	rand.Seed(time.Now().UnixNano())

	rt := &router{}
	rt.edns.Store(uint32(cfg.EDNSBuf))

	gr := newGeoResolver(cfg.GeoIP)
	sup = newSupervisor()
	mux, auths := buildMux(cfg, gr, sup)
	rt.inner.Store(mux)

	current.mu.Lock()
	current.cfg = cfg
	current.rt = rt
	current.logW = w
	current.auths = auths
	current.geo = gr
	current.mu.Unlock()

	go sampleMemStats()
	startListeners(rt, cfg, cfg.MaxWorkers)

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
		go func() {
			log.Printf("admin https listening on %s", apiListen)
			if err := http.ListenAndServeTLS(apiListen, apiCert, apiKey, mux); err != nil {
				log.Printf("admin https: %v", err)
			}
		}()
	}

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
	if cfg.TimeoutSec == 0 {
		cfg.TimeoutSec = 5
	}
	if cfg.IntervalSec == 0 {
		cfg.IntervalSec = 8
	}
	if cfg.Rise == 0 {
		cfg.Rise = 2
	}
	if cfg.Fall == 0 {
		cfg.Fall = 4
	}
	if cfg.EDNSBuf == 0 {
		cfg.EDNSBuf = 1232
	}
	if cfg.MaxRecords < 0 {
		cfg.MaxRecords = 0
	}
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = runtime.NumCPU()
	}
	if cfg.JitterMs < 0 {
		cfg.JitterMs = 0
	}
	if cfg.CooldownSec == 0 {
		cfg.CooldownSec = 25
	}

	if cfg.DNS64Prefix == "" {
		cfg.DNS64Prefix = "64:ff9b::"
	}

	if cfg.LogFile == "" && !cfg.LogSyslog {
		cfg.LogFile = "/var/log/breathgslb/breathgslb.log"
	}
	if cfg.GeoIP != nil {
		if cfg.GeoIP.PreferField == "" {
			cfg.GeoIP.PreferField = "registered"
		}
		if cfg.GeoIP.CacheTTLSec == 0 {
			cfg.GeoIP.CacheTTLSec = 600
		}
	}
}

// generateTSIGKeys populates missing TSIG secrets and optionally writes them to disk.
func generateTSIGKeys(cfg *Config) {
	if cfg.TSIG == nil {
		return
	}
	var keyDir string
	if cfg.TSIG.Path != "" {
		keyDir = cfg.TSIG.Path
		_ = os.MkdirAll(keyDir, 0o755)
	}
	for zi := range cfg.Zones {
		z := &cfg.Zones[zi]
		if z.TSIG == nil {
			continue
		}
		defAlg := z.TSIG.DefaultAlgorithm
		if defAlg == "" {
			defAlg = "hmac-sha256"
		}
		seed := ""
		if z.TSIG.SeedEnv != "" {
			seed = os.Getenv(z.TSIG.SeedEnv)
		}
		for ki := range z.TSIG.Keys {
			k := &z.TSIG.Keys[ki]
			if k.Algorithm == "" {
				k.Algorithm = defAlg
			}
			if k.Secret == "" {
				if seed != "" {
					k.Secret = deriveTSIGSecret(seed, k.Name, z.TSIG.Epoch)
				} else {
					k.Secret = randomTSIGSecret()
				}
			}
			if keyDir != "" {
				saveTSIGKey(keyDir, *k)
			}
		}
	}
}

func deriveTSIGSecret(seed, name string, epoch int) string {
	h := hmac.New(sha256.New, []byte(seed))
	h.Write([]byte(fmt.Sprintf("%s|%d", name, epoch)))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func randomTSIGSecret() string {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func saveTSIGKey(dir string, k TSIGKey) {
	name := strings.TrimSuffix(k.Name, ".")
	path := filepath.Join(dir, name+".key")
	content := fmt.Sprintf("key \"%s\" {\n    algorithm %s;\n    secret \"%s\";\n};\n", k.Name, k.Algorithm, k.Secret)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		log.Printf("tsig: write %s: %v", path, err)
	}
}

func setupLogging(cfg *Config) io.WriteCloser {
	if cfg.LogSyslog {
		w, err := setupSyslogLogging()
		if err != nil {
			log.Printf("warn: cannot connect to syslog: %v; using stderr only", err)
			return nil
		}
		return w
	}
	path := cfg.LogFile
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

func reopenLogging(cfg *Config) {
	current.mu.Lock()
	defer current.mu.Unlock()
	if current.logW != nil {
		_ = current.logW.Close()
	}
	current.logW = setupLogging(cfg)
	current.cfg.LogFile = cfg.LogFile
	current.cfg.LogSyslog = cfg.LogSyslog
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	if err := generateReverseZones(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func buildMux(cfg *Config, gr *geoResolver, sup *supervisor) (dns.Handler, map[string]*authority) {
	mux := dns.NewServeMux()
	auths := make(map[string]*authority)
	for _, z := range cfg.Zones {
		zname := ensureDot(z.Name)
		ctx, cancel := context.WithCancel(context.Background())
		st := &state{cooldown: time.Duration(cfg.CooldownSec) * time.Second}
		auth := &authority{cfg: cfg, zone: z, state: st, ctx: ctx, cancel: cancel, geo: gr}
		auth.serial = uint32(time.Now().Unix())
		// DNSSEC keys & index
		auth.keys = loadDNSSEC(z)
		auth.zidx = buildIndex(z)
		// parse local CIDRs once
		auth.cidrInit()

		mux.HandleFunc(zname, auth.handle)
		auths[zname] = auth
		if sup != nil {
			sup.watch(ctx, zname+" healthLoop", auth.healthLoop)
			sup.watch(ctx, zname+" purgeLoop", auth.purgeLoop)
		} else {
			go auth.healthLoop()
			go auth.purgeLoop()
		}
		log.Printf("serving zone %s", zname)
	}
	return mux, auths
}

type bindTarget struct{ netw, addr string }

func targetsFromConfig(cfg *Config) []bindTarget {
	var t []bindTarget
	port := derivePort(cfg.Listen)
	seen := map[string]bool{}
	add := func(netw, addr string) {
		key := netw + "|" + addr
		if !seen[key] {
			t = append(t, bindTarget{netw, addr})
			seen[key] = true
		}
	}

	// 1) explicit listen_addrs take precedence
	if len(cfg.ListenAddrs) > 0 {
		for _, la := range cfg.ListenAddrs {
			la = strings.TrimSpace(la)
			if la == "" {
				continue
			}
			host, p, err := net.SplitHostPort(la)
			if err != nil {
				// allow bare IP or bare port
				if i := strings.LastIndex(la, ":"); i >= 0 && i < len(la)-1 {
					host = la[:i]
					p = la[i+1:]
				} else {
					host = la
					p = port
				}
			}
			if host == "" || host == "0.0.0.0" {
				add("udp4", "0.0.0.0:"+p)
				add("tcp4", "0.0.0.0:"+p)
			} else if host == "::" || host == "[::]" || strings.Contains(host, ":") {
				h := strings.Trim(host, "[]")
				add("udp6", "["+h+"]:"+p)
				add("tcp6", "["+h+"]:"+p)
			} else {
				ip := net.ParseIP(host)
				if ip != nil && ip.To4() == nil {
					add("udp6", "["+ip.String()+"]:"+p)
					add("tcp6", "["+ip.String()+"]:"+p)
				}
				if ip == nil || ip.To4() != nil {
					add("udp4", host+":"+p)
					add("tcp4", host+":"+p)
				}
			}
		}
		return t
	}

	// 2) interfaces: derive bind IPs from interface addresses
	if len(cfg.Interfaces) > 0 {
		for _, ifn := range cfg.Interfaces {
			ifn = strings.TrimSpace(ifn)
			if ifn == "" {
				continue
			}
			ifi, err := net.InterfaceByName(ifn)
			if err != nil {
				log.Printf("warn: interface %s not found: %v", ifn, err)
				continue
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				log.Printf("warn: cannot read addrs for %s: %v", ifn, err)
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil {
					continue
				}
				if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
					continue
				}
				if ip.To4() != nil {
					add("udp4", ip.String()+":"+port)
					add("tcp4", ip.String()+":"+port)
				} else {
					add("udp6", "["+ip.String()+"]:"+port)
					add("tcp6", "["+ip.String()+"]:"+port)
				}
			}
		}
		if len(t) > 0 {
			return t
		}
		log.Printf("warn: no usable addresses from interfaces; falling back to all-addrs")
	}

	// 3) default: bind on all addresses both families
	add("udp4", "0.0.0.0:"+port)
	add("udp6", "[::]:"+port)
	add("tcp4", "0.0.0.0:"+port)
	add("tcp6", "[::]:"+port)
	return t
}

func startListeners(rt *router, cfg *Config, workers int) {
	addrs := targetsFromConfig(cfg)
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	for _, a := range addrs {
		if strings.HasPrefix(a.netw, "udp") {
			pc, err := listenUDP(a.netw, a.addr)
			if err != nil {
				log.Fatalf("listen %s %s: %v", a.netw, a.addr, err)
			}
			uc := pc.(*net.UDPConn)
			log.Printf("listening on %s %s", a.netw, a.addr)
			for i := 0; i < workers; i++ {
				go serveUDPWorker(rt, uc)
			}
			continue
		}
		srv := &dns.Server{Net: a.netw, Addr: a.addr, Handler: rt, ReusePort: true}
		log.Printf("listening on %s %s", a.netw, a.addr)
		go func(s *dns.Server) {
			if err := s.ListenAndServe(); err != nil {
				log.Fatalf("listen %s %s: %v", s.Net, s.Addr, err)
			}
		}(srv)
	}
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
	w.Write(openapiSpec)
}

func swaggerHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(swaggerPage)
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

func serveUDPWorker(h dns.Handler, conn *net.UDPConn) {
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, sess, err := dns.ReadFromSessionUDP(conn, buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}
		w := &udpResponseWriter{conn: conn, session: sess}
		h.ServeDNS(w, req)
	}
}

func reload(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	setupDefaults(cfg)
	generateTSIGKeys(cfg)

	newGeo := newGeoResolver(cfg.GeoIP)
	mux, auths := buildMux(cfg, newGeo, sup)

	current.mu.Lock()
	old := current.auths
	oldGeo := current.geo
	current.rt.inner.Store(mux)
	current.rt.edns.Store(uint32(cfg.EDNSBuf))
	current.cfg = cfg
	current.auths = auths
	current.geo = newGeo
	current.mu.Unlock()

	for _, a := range old {
		a.cancel()
	}
	reopenLogging(cfg)
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
	m.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := ensureDot(q.Name)
	z := ensureDot(a.zone.Name)

	if a.cfg.LogQueries {
		log.Printf("query %s %s", name, dns.TypeToString[q.Qtype])
	}

	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		if name != z {
			m.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		a.xfr(w, r, q.Qtype == dns.TypeIXFR)
		return
	}

	// Basic apex handling for SOA/NS/DNSKEY
	if name == z {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, a.soa())
		case dns.TypeNS:
			for _, ns := range a.zone.NS {
				m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
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
			m.Ns = append(m.Ns, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
		}
		m.Ns = append(m.Ns, a.soa())
		if wantDNSSEC(r) && a.keys != nil && a.keys.enabled {
			if a.zidx != nil && a.zidx.hasName(name) {
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

func (a *authority) xfr(w dns.ResponseWriter, r *dns.Msg, ixfr bool) {
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
				}
			}
		}
		records := a.axfrRecords()
		rrset := append([]dns.RR{soa}, records...)
		records = nil
		rrset = append(rrset, soa)
		ch <- &dns.Envelope{RR: rrset}
		rrset = nil
		close(ch)
	}()
	if err := tr.Out(w, r, ch); err != nil {
		log.Printf("xfr for %s failed: %v", a.zone.Name, err)
	}
	_ = w.Close()
}

func (a *authority) axfrRecords() []dns.RR {
	var rrs []dns.RR
	z := ensureDot(a.zone.Name)
	for _, ns := range a.zone.NS {
		rrs = append(rrs, &dns.NS{Hdr: hdr(z, dns.TypeNS, a.zone.TTLSOA), Ns: ensureDot(ns)})
	}
	rrs = append(rrs, a.buildA(ipsFrom(a.zone.AMaster))...)
	rrs = append(rrs, a.buildA(ipsFrom(a.zone.AStandby))...)
	rrs = append(rrs, a.buildA(ipsFrom(a.zone.AFallback))...)
	rrs = append(rrs, a.buildA(ipsFrom(a.zone.AMasterPrivate))...)
	rrs = append(rrs, a.buildA(ipsFrom(a.zone.AStandbyPrivate))...)
	rrs = append(rrs, a.buildA(ipsFrom(a.zone.AFallbackPrivate))...)
	rrs = append(rrs, a.buildAAAA(ipsFrom(a.zone.AAAAMaster))...)
	rrs = append(rrs, a.buildAAAA(ipsFrom(a.zone.AAAAStandby))...)
	rrs = append(rrs, a.buildAAAA(ipsFrom(a.zone.AAAAFallback))...)
	rrs = append(rrs, a.buildAAAA(ipsFrom(a.zone.AAAAMasterPrivate))...)
	rrs = append(rrs, a.buildAAAA(ipsFrom(a.zone.AAAAStandbyPrivate))...)
	rrs = append(rrs, a.buildAAAA(ipsFrom(a.zone.AAAAFallbackPrivate))...)
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
	if ensureDot(owner) != ensureDot(a.zone.Name) {
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
		addrs = ipsFrom(a.zone.AMaster)
	} else if sV4 && len(a.zone.AStandby) > 0 {
		addrs = ipsFrom(a.zone.AStandby)
	} else if len(a.zone.AFallback) > 0 {
		addrs = ipsFrom(a.zone.AFallback)
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
	if ensureDot(owner) != ensureDot(a.zone.Name) {
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
		addrs = ipsFrom(a.zone.AAAAMaster)
	} else if sV6 && len(a.zone.AAAAStandby) > 0 {
		addrs = ipsFrom(a.zone.AAAAStandby)
	} else if len(a.zone.AAAAFallback) > 0 {
		addrs = ipsFrom(a.zone.AAAAFallback)
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

func (a *authority) privateFor(tier string, ipv6 bool) []dns.RR {
	switch tier {
	case "master":
		if !ipv6 && len(a.zone.AMasterPrivate) > 0 {
			return a.buildA(ipsFrom(a.zone.AMasterPrivate))
		}
		if ipv6 && len(a.zone.AAAAMasterPrivate) > 0 {
			return a.buildAAAA(ipsFrom(a.zone.AAAAMasterPrivate))
		}
	case "standby":
		if !ipv6 && len(a.zone.AStandbyPrivate) > 0 {
			return a.buildA(ipsFrom(a.zone.AStandbyPrivate))
		}
		if ipv6 && len(a.zone.AAAAStandbyPrivate) > 0 {
			return a.buildAAAA(ipsFrom(a.zone.AAAAStandbyPrivate))
		}
	case "fallback":
		if !ipv6 && len(a.zone.AFallbackPrivate) > 0 {
			return a.buildA(ipsFrom(a.zone.AFallbackPrivate))
		}
		if ipv6 && len(a.zone.AAAAFallbackPrivate) > 0 {
			return a.buildAAAA(ipsFrom(a.zone.AAAAFallbackPrivate))
		}
	}
	return nil
}

func (a *authority) publicFor(tier string, ipv6 bool) []dns.RR {
	switch tier {
	case "master":
		if !ipv6 {
			return a.buildA(ipsFrom(a.zone.AMaster))
		}
		return a.buildAAAA(ipsFrom(a.zone.AAAAMaster))
	case "standby":
		if !ipv6 {
			return a.buildA(ipsFrom(a.zone.AStandby))
		}
		return a.buildAAAA(ipsFrom(a.zone.AAAAStandby))
	default:
		if !ipv6 {
			return a.buildA(ipsFrom(a.zone.AFallback))
		}
		return a.buildAAAA(ipsFrom(a.zone.AAAAFallback))
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
	z := ensureDot(a.zone.Name)
	nsPrimary := ensureDot(a.zone.NS[0])
	return &dns.SOA{Hdr: hdr(z, dns.TypeSOA, a.zone.TTLSOA), Ns: nsPrimary, Mbox: ensureDot(a.zone.Admin), Serial: a.serial, Refresh: 60, Retry: 30, Expire: 600, Minttl: a.zone.TTLSOA}
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

func effectiveHealth(zoneName string, zh *HealthConfig) HealthConfig {
	// Start with a shallow copy so defaults don't mutate the caller's config.
	var h HealthConfig

	if zh != nil && zh.Kind != "" {
		h.Kind = zh.Kind
	}
	if h.Kind == "" {
		h.Kind = HKHTTP
	}
	if h.Port == 0 {
		switch h.Kind {
		case HKHTTP:
			if h.Scheme == "" {
				h.Scheme = "https"
			}
			if h.Scheme == "http" {
				h.Port = 80
			} else {
				h.Port = 443
			}
		case HKTCP:
			h.Port = 443
		case HKUDP:
			h.Port = 53
		case HKICMP, HKRawIP: /* no port */
		}
	}

	if zh != nil {
		if zh.Scheme != "" {
			h.Scheme = zh.Scheme
		}
		if zh.Method != "" {
			h.Method = zh.Method
		}
		if zh.Port != 0 {
			h.Port = zh.Port
		}
		if zh.ALPN != "" {
			h.ALPN = zh.ALPN
		}
		if zh.HostHeader != "" {
			h.HostHeader = zh.HostHeader
		}
		if zh.Path != "" {
			h.Path = zh.Path
		}
		if zh.SNI != "" {
			h.SNI = zh.SNI
		}
		if zh.InsecureTLS {
			h.InsecureTLS = true
		}
		if zh.Protocol != 0 {
			h.Protocol = zh.Protocol
		}
		if zh.Expect != "" {
			h.Expect = zh.Expect
		}
	}
	if h.Path == "" && (h.Kind == HKHTTP || h.Kind == HKHTTP3) {
		h.Path = "/health"
	}
	zoneHost := strings.TrimSuffix(zoneName, ".")
	if h.HostHeader == "" {
		h.HostHeader = zoneHost
	}
	if h.SNI == "" {
		h.SNI = h.HostHeader
	}
	if h.Scheme == "" {
		h.Scheme = "https"
	}
	if h.Method == "" {
		h.Method = http.MethodGet
	}
	if h.Port == 0 {
		switch h.Kind {
		case HKHTTP:
			if h.Scheme == "http" {
				h.Port = 80
			} else {
				h.Port = 443
			}
		case HKHTTP3:
			h.Port = 443
		case HKTCP:
			h.Port = 443
		case HKUDP:
			h.Port = 53
		case HKICMP:
			// no port
		}
	}
	return h
}

func tcpCheck(ctx context.Context, ip string, h HealthConfig) error {
	addr := net.JoinHostPort(ip, strconv.Itoa(h.Port))
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if h.TLSEnable {
		sni := firstNonEmpty(h.SNI, h.HostHeader)
		cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: h.InsecureTLS}
		if h.ALPN != "" {
			cfg.NextProtos = strings.Split(h.ALPN, ",")
		}
		tconn := tls.Client(conn, cfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			return err
		}
		defer tconn.Close()
	}
	return nil
}

func udpCheck(ctx context.Context, ip string, h HealthConfig) error {
	addr := net.JoinHostPort(ip, strconv.Itoa(h.Port))
	uc, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer uc.Close()

	payload := []byte("ping")
	if h.UDPPayloadB64 != "" {
		if dec, e := base64.StdEncoding.DecodeString(h.UDPPayloadB64); e == nil {
			payload = dec
		}
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(deadline)
	}

	if _, err = uc.Write(payload); err != nil {
		return err
	}

	if h.UDPExpectRE == "" {
		// fire-and-forget: if no ICMP error, consider OK
		// Try a short read to catch immediate errors
		buf := make([]byte, 4)
		uc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = uc.Read(buf)
		return nil
	}

	// Expect response matching regex
	buf := make([]byte, 1500)
	n, err := uc.Read(buf)
	if err != nil {
		return err
	}
	re, err := regexp.Compile(h.UDPExpectRE)
	if err != nil {
		return err
	}
	if !re.Match(buf[:n]) {
		return fmt.Errorf("udp expect failed")
	}
	return nil
}

func rawIPCheck(ctx context.Context, ip string, h HealthConfig) error {
	if h.Protocol <= 0 {
		return fmt.Errorf("rawip protocol must be >0")
	}
	p := net.ParseIP(ip)
	if p == nil {
		return fmt.Errorf("bad ip %q", ip)
	}
	network := fmt.Sprintf("ip4:%d", h.Protocol)
	if p.To4() == nil {
		network = fmt.Sprintf("ip6:%d", h.Protocol)
	}
	c, err := net.ListenPacket(network, "")
	if err != nil {
		return err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err = c.WriteTo([]byte{0}, &net.IPAddr{IP: p}); err != nil {
		return err
	}
	buf := make([]byte, 1)
	_, _, err = c.ReadFrom(buf)
	return err
}

func icmpCheck(ctx context.Context, ip string, h HealthConfig) error {
	p := net.ParseIP(ip)
	if p == nil {
		return fmt.Errorf("bad ip %q", ip)
	}

	var network string
	var echoType icmp.Type
	if p.To4() != nil {
		network = "ip4:icmp"
		echoType = ipv4.ICMPTypeEcho
	} else {
		// On many platforms the network name for IPv6 ICMP is "ip6:ipv6-icmp".
		// Go also accepts the numeric protocol "ip6:58".
		network = "ip6:ipv6-icmp"
		echoType = ipv6.ICMPTypeEchoRequest
	}

	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		return err
	}
	defer c.Close()

	payload := []byte("breathgslb")
	if h.ICMPPayloadB64 != "" {
		if dec, err := base64.StdEncoding.DecodeString(h.ICMPPayloadB64); err == nil {
			payload = dec
		}
	}

	wm := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: payload,
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}

	// apply context deadline to the socket
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	if _, err = c.WriteTo(wb, &net.IPAddr{IP: p}); err != nil {
		return err
	}

	rb := make([]byte, 1500)
	for {
		n, _, err := c.ReadFrom(rb)
		if err != nil {
			return err
		}
		rm, err := icmp.ParseMessage(func() int {
			if p.To4() != nil {
				return 1
			} // ICMP
			return 58 // ICMPv6
		}(), rb[:n])
		if err != nil {
			return err
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			return nil
		default:
			// ignore non-echo-reply messages
		}
	}
}

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

	hc := effectiveHealth(a.zone.Name, a.zone.Health)

	// master v4

	m4 := probeAny(ctx, ipsFrom(a.zone.AMaster), hc)
	a.state.set("master", false, m4, a.cfg.Rise, a.cfg.Fall)
	// master v6
	m6 := probeAny(ctx, ipsFrom(a.zone.AAAAMaster), hc)
	a.state.set("master", true, m6, a.cfg.Rise, a.cfg.Fall)
	// standby v4
	s4 := probeAny(ctx, ipsFrom(a.zone.AStandby), hc)
	a.state.set("standby", false, s4, a.cfg.Rise, a.cfg.Fall)
	// standby v6
	s6 := probeAny(ctx, ipsFrom(a.zone.AAAAStandby), hc)
	a.state.set("standby", true, s6, a.cfg.Rise, a.cfg.Fall)
}

func probeAny(ctx context.Context, ips []string, hc HealthConfig) bool {
	for _, ip := range ips {
		p := net.ParseIP(ip)
		if p == nil {
			continue
		}

		var err error
		switch hc.Kind {
		case HKHTTP, "":
			err = httpCheck(ctx, ip, hc)
		case HKHTTP3:
			err = http3Check(ctx, ip, hc)
		case HKTCP:
			err = tcpCheck(ctx, ip, hc)
		case HKUDP:
			err = udpCheck(ctx, ip, hc)
		case HKICMP:
			err = icmpCheck(ctx, ip, hc)
		case HKRawIP:
			err = rawIPCheck(ctx, ip, hc)
		default:
			err = fmt.Errorf("unknown health kind %q", hc.Kind)
		}
		if err == nil {
			return true
		}
	}
	ips = nil
	return false
}

func http3Check(ctx context.Context, ip string, hc HealthConfig) error {
	path := hc.Path
	if path == "" {
		path = "/health"
	}
	host := ip
	if strings.Contains(ip, ":") {
		host = "[" + ip + "]"
	}
	url := fmt.Sprintf("%s://%s:%d%s", hc.Scheme, host, hc.Port, path)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: hc.InsecureTLS, ServerName: firstNonEmpty(hc.SNI, hc.HostHeader)}}
	defer tr.Close()
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequestWithContext(ctx, hc.Method, url, nil)
	if hc.HostHeader != "" {
		req.Host = hc.HostHeader
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if hc.Expect != "" {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if err != nil {
				return err
			}
			if !strings.Contains(string(body), hc.Expect) {
				return fmt.Errorf("expect not found")
			}
		}
		return nil
	}
	return fmt.Errorf("status %d", resp.StatusCode)
}

func httpCheck(ctx context.Context, ip string, hc HealthConfig) error {
	path := hc.Path
	if path == "" {
		path = "/health"
	}
	host := ip
	if strings.Contains(ip, ":") {
		host = "[" + ip + "]"
	}
	url := fmt.Sprintf("%s://%s:%d%s", hc.Scheme, host, hc.Port, path)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: hc.InsecureTLS, ServerName: firstNonEmpty(hc.SNI, hc.HostHeader)}}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequestWithContext(ctx, hc.Method, url, nil)
	if hc.HostHeader != "" {
		req.Host = hc.HostHeader
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if hc.Expect != "" {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if err != nil {
				return err
			}
			if !strings.Contains(string(body), hc.Expect) {
				return fmt.Errorf("expect not found")
			}
		}
		return nil
	}
	return fmt.Errorf("status %d", resp.StatusCode)
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

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func derivePort(listen string) string {
	if listen == "" {
		return "53"
	}
	_, port, err := net.SplitHostPort(listen)
	if err == nil && port != "" {
		return port
	}
	i := strings.LastIndex(listen, ":")
	if i >= 0 && i < len(listen)-1 {
		return listen[i+1:]
	}
	return "53"
}

// ---- DNSSEC helpers ----

func wantDNSSEC(r *dns.Msg) bool {
	if o := r.IsEdns0(); o != nil {
		return o.Do()
	}
	return false
}

func loadDNSSEC(z Zone) *dnssecKeys {
	if z.DNSSEC == nil || !z.DNSSEC.Enable {
		return &dnssecKeys{enabled: false}
	}
	baseZ := strings.TrimSuffix(ensureDot(z.Name), ".")
	zsk := z.DNSSEC.ZSKFile
	ksk := z.DNSSEC.KSKFile
	if zsk == "" {
		return &dnssecKeys{enabled: false}
	}
	if ksk == "" {
		ksk = zsk
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

// NSEC support for existing names only (NXRRSET). We'll extend to full NXDOMAIN later.
func (a *authority) makeNSEC(owner string) dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	if a.zidx == nil {
		return nil
	}
	idx := a.zidx
	if !idx.hasName(owner) {
		return nil
	}
	next := idx.nextName(owner)
	bm := idx.typeBitmap(owner)
	return &dns.NSEC{Hdr: hdr(ensureDot(owner), dns.TypeNSEC, a.zone.TTLAnswer), NextDomain: ensureDot(next), TypeBitMap: bm}
}

// ---- zone index helpers ----
