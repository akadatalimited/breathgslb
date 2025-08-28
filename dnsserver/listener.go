package dnsserver

import (
	"log"
	"net"
	"runtime"
	"strings"

	"github.com/miekg/dns"

	"github.com/akadatalimited/breathgslb/config"
)

type bindTarget struct{ netw, addr string }

// StartListeners binds network listeners based on configuration.
func StartListeners(h dns.Handler, cfg *config.Config, workers int) {
	addrs := targetsFromConfig(cfg)
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	logged := map[string]bool{}
	for _, a := range addrs {
		key := a.netw + "|" + a.addr
		if strings.HasPrefix(a.netw, "udp") {
			pc, err := listenUDP(a.netw, a.addr)
			if err != nil {
				log.Fatalf("listen %s %s: %v", a.netw, a.addr, err)
			}
			uc := pc.(*net.UDPConn)
			if !logged[key] {
				log.Printf("listening on %s %s", a.netw, a.addr)
				logged[key] = true
			}
			for i := 0; i < workers; i++ {
				go serveUDPWorker(h, uc)
			}
			continue
		}
		srv := &dns.Server{Net: a.netw, Addr: a.addr, Handler: h, ReusePort: true}
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
	port := derivePort(cfg.Listen)

	normalize := func(addr string) string {
		host, p, err := net.SplitHostPort(addr)
		if err != nil {
			return addr
		}
		h := strings.Trim(host, "[]")
		if ip := net.ParseIP(h); ip != nil {
			host = ip.String()
		} else {
			host = h
		}
		if strings.Contains(host, ":") {
			return "[" + host + "]:" + p
		}
		return host + ":" + p
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
			host, p, err := net.SplitHostPort(la)
			if err != nil {
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
	add("udp4", "0.0.0.0:"+port)
	add("udp6", "[::]:"+port)
	add("tcp4", "0.0.0.0:"+port)
	add("tcp6", "[::]:"+port)
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

func serveUDPWorker(h dns.Handler, conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		msg := &dns.Msg{}
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		rw := &responseWriter{conn: conn, addr: addr}
		h.ServeDNS(rw, msg)
	}
}

type responseWriter struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (rw *responseWriter) LocalAddr() net.Addr  { return rw.conn.LocalAddr() }
func (rw *responseWriter) RemoteAddr() net.Addr { return rw.addr }
func (rw *responseWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = rw.conn.WriteToUDP(b, rw.addr)
	return err
}
func (rw *responseWriter) Write([]byte) (int, error) { return 0, nil }
func (rw *responseWriter) Close() error              { return nil }
func (rw *responseWriter) TsigStatus() error         { return nil }
func (rw *responseWriter) TsigTimersOnly(bool)       {}
func (rw *responseWriter) Hijack()                   {}
