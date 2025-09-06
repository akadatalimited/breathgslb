package main

import (
	"context"
	"fmt"
	"log"
	"net"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/akadatalimited/breathgslb/src/dnsserver"
	"github.com/akadatalimited/breathgslb/src/doc"
	"github.com/akadatalimited/breathgslb/src/healthcheck"
	"github.com/akadatalimited/breathgslb/src/logging"
	"github.com/miekg/dns"

	maxminddb "github.com/oschwald/maxminddb-golang"
)



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



