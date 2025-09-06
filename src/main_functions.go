package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
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
var buildOS string
var supportExpiry time.Time

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

// validateLicense decrypts an AES-256 encrypted payload using key and validates
// the license against the compiled build OS. If the license is valid, the key
// is written to /etc/breathgslb/license.
func validateLicense(key string, payload []byte) error {
	k := []byte(key)
	if len(k) != 32 {
		return fmt.Errorf("invalid key length")
	}
	if len(payload) == 0 {
		return fmt.Errorf("license payload missing")
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ns := aead.NonceSize()
	if len(payload) < ns {
		return fmt.Errorf("payload too short")
	}
	nonce := payload[:ns]
	ciphertext := payload[ns:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	var lp licensePayload
	if err := json.Unmarshal(plaintext, &lp); err != nil {
		return err
	}
	binOS := buildOS
	if binOS == "" {
		binOS = runtime.GOOS
	}
	if !strings.EqualFold(baseOS(lp.OS), baseOS(binOS)) {
		return fmt.Errorf("os mismatch")
	}

	supportExpiry = time.Time{}
	if lp.Supported {
		se, err := time.Parse("2006-01-02", lp.SupportExpiry)
		if err != nil {
			return fmt.Errorf("invalid support expiry: %w", err)
		}
		supportExpiry = se
	}
	if err := os.MkdirAll("/etc/breathgslb", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/breathgslb/license", []byte(key), 0600); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/breathgslb/license.payload", []byte(base64.StdEncoding.EncodeToString(payload)), 0600); err != nil {
		return err
	}
	status := "inactive"
	if isSupportActive() {
		status = "active"
	}
	if err := os.WriteFile("/etc/breathgslb/support", []byte(status), 0600); err != nil {
		return err
	}
	return nil
}

func isSupportActive() bool {
	return !supportExpiry.IsZero() && time.Now().Before(supportExpiry)
}

func supportStatus() (bool, int) {
	days := 0
	if !supportExpiry.IsZero() {
		days = int(time.Until(supportExpiry).Hours() / 24)
		if days < 0 {
			days = 0
		}
	}
	return isSupportActive(), days
}

func baseOS(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "linux"):
		return "linux"
	case strings.HasPrefix(s, "darwin"):
		return "darwin"
	case strings.HasPrefix(s, "windows"):
		return "windows"
	case strings.Contains(s, "bsd"):
		return "bsd"
	default:
		return s
	}
}

type licensePayload struct {
	OS            string `json:"os"`
	Email         string `json:"email"`
	Salt          string `json:"salt"`
	SupportExpiry string `json:"support_expiry"`
	Supported     bool   `json:"supported"`
	CustomerType  string `json:"customer_type"`
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
	var licensePayloadStr string

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
	flag.StringVar(&licensePayloadStr, "license-payload", "", "base64-encoded license payload")
	flag.StringVar(&licensePayloadStr, "lp", "", "base64-encoded license payload")
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

	if licensePayloadStr == "" {
		if b, err := os.ReadFile("/etc/breathgslb/license.payload"); err == nil {
			licensePayloadStr = strings.TrimSpace(string(b))
		} else {
			log.Fatalf("license payload required")
		}
	}
	licensePayloadBytes, err := base64.StdEncoding.DecodeString(licensePayloadStr)
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
	tsigSecrets := config.TSIGSecretMap(cfg)

	// Set CPU and thread limits
	if cfg.MaxCPUCores > 0 {
		runtime.GOMAXPROCS(cfg.MaxCPUCores)
		log.Printf("Set maximum CPU cores to %d", cfg.MaxCPUCores)
	}
	if cfg.MaxThreads > 0 {
		// This is a soft limit - Go doesn't provide a hard limit for threads
		// but we can set GOMAXPROCS which limits the number of OS threads
		// that can execute user-level Go code simultaneously
		log.Printf("Configured for maximum %d threads", cfg.MaxThreads)
	}

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
	dnsserver.StartListeners(rt, cfg, cfg.MaxWorkers, tsigSecrets)

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