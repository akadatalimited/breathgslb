package dnsserver

import (
	"log"
	"net"
	"runtime"
	"strings"

	"github.com/miekg/dns"

	"github.com/akadatalimited/breathgslb/src/config"
)

type bindTarget struct{ netw, addr string }

// StartListeners binds network listeners based on configuration.
// The secrets map should contain all TSIG keys across configured zones.
// It may be nil if no keys are configured.
func StartListeners(h dns.Handler, cfg *config.Config, workers int, secrets map[string]string) {
	addrs := targetsFromConfig(cfg)
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	logged := map[string]bool{}
	for _, a := range addrs {
		key := a.netw + "|" + a.addr
		if strings.HasPrefix(a.netw, "udp") {
			if !logged[key] {
				log.Printf("listening on %s %s", a.netw, a.addr)
				logged[key] = true
			}
			if runtime.GOOS == "windows" {
				pc, err := listenUDP(a.netw, a.addr)
				if err != nil {
					log.Fatalf("listen %s %s: %v", a.netw, a.addr, err)
				}
				srv := &dns.Server{PacketConn: pc, Handler: h, TsigSecret: secrets}
				go func(netw, addr string, s *dns.Server) {
					if err := s.ActivateAndServe(); err != nil {
						log.Fatalf("listen %s %s: %v", netw, addr, err)
					}
				}(a.netw, a.addr, srv)
				continue
			}
			for i := 0; i < workers; i++ {
				pc, err := listenUDP(a.netw, a.addr)
				if err != nil {
					log.Fatalf("listen %s %s: %v", a.netw, a.addr, err)
				}
				srv := &dns.Server{PacketConn: pc, Handler: h, TsigSecret: secrets}
				go func(netw, addr string, s *dns.Server) {
					if err := s.ActivateAndServe(); err != nil {
						log.Fatalf("listen %s %s: %v", netw, addr, err)
					}
				}(a.netw, a.addr, srv)
			}
			continue
		}
		srv := &dns.Server{Net: a.netw, Addr: a.addr, Handler: h, ReusePort: true, TsigSecret: secrets}
		if !logged[key] {
			log.Printf("listening on %s %s", a.netw, a.addr)
			logged[key] = true
		}
		go func(s *dns.Server) {
			if err := s.ListenAndServe(); err != nil {
				log.Fatalf("listen %s %s: %v", s.Net, s.Addr, err)
			}
		}(srv)
	}
}

func targetsFromConfig(cfg *config.Config) []bindTarget {
	var t []bindTarget
	defaultPort := derivePort(cfg.Listen)

	normalize := func(addr string) string {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return addr
		}
		trimmedHost := strings.Trim(host, "[]")
		if ip := net.ParseIP(trimmedHost); ip != nil {
			host = ip.String()
		} else {
			host = trimmedHost
		}
		if strings.Contains(host, ":") {
			return "[" + host + "]:" + port
		}
		return host + ":" + port
	}

	seen := map[string]map[string]bool{}
	add := func(netw, addr string) {
		addr = normalize(addr)
		if seen[netw] == nil {
			seen[netw] = map[string]bool{}
		}
		if !seen[netw][addr] {
			t = append(t, bindTarget{netw, addr})
			seen[netw][addr] = true
		}
	}
	if len(cfg.ListenAddrs) > 0 {
		for _, la := range cfg.ListenAddrs {
			la = strings.TrimSpace(la)
			if la == "" {
				continue
			}
			host, port, err := net.SplitHostPort(la)
			if err != nil {
				if i := strings.LastIndex(la, ":"); i >= 0 && i < len(la)-1 {
					host = la[:i]
					port = la[i+1:]
				} else {
					host = la
					port = defaultPort
				}
			}
			if host == "" || host == "0.0.0.0" {
				add("udp4", "0.0.0.0:"+port)
				add("tcp4", "0.0.0.0:"+port)
			} else if host == "::" || host == "[::]" || strings.Contains(host, ":") {
				trimmedHost := strings.Trim(host, "[]")
				add("udp6", "["+trimmedHost+"]:"+port)
				add("tcp6", "["+trimmedHost+"]:"+port)
			} else {
				ip := net.ParseIP(host)
				if ip != nil && ip.To4() == nil {
					add("udp6", "["+ip.String()+"]:"+port)
					add("tcp6", "["+ip.String()+"]:"+port)
				}
				if ip == nil || ip.To4() != nil {
					add("udp4", host+":"+port)
					add("tcp4", host+":"+port)
				}
			}
		}
		return t
	}
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
				// Only bind routable, non-special interface addresses here; wildcard fallback binding may be added later.
				if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
					continue
				}
				if ip.To4() != nil {
					add("udp4", ip.String()+":"+defaultPort)
					add("tcp4", ip.String()+":"+defaultPort)
				} else {
					add("udp6", "["+ip.String()+"]:"+defaultPort)
					add("tcp6", "["+ip.String()+"]:"+defaultPort)
				}
			}
		}
		if len(t) > 0 {
			return t
		}
		log.Printf("warn: no usable addresses from interfaces; falling back to all-addrs")
	}
	add("udp4", "0.0.0.0:"+defaultPort)
	add("udp6", "[::]:"+defaultPort)
	add("tcp4", "0.0.0.0:"+defaultPort)
	add("tcp6", "[::]:"+defaultPort)
	return t
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
