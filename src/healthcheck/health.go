package healthcheck

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/akadatalimited/breathgslb/src/config"
)

// Effective returns the final HealthConfig for a zone name and optional override.
func Effective(zoneName string, zh *config.HealthConfig) config.HealthConfig {
	var h config.HealthConfig
	if zh != nil && zh.Kind != "" {
		h.Kind = zh.Kind
	}
	if h.Kind == "" {
		h.Kind = config.HKHTTP
	}
	if h.Port == 0 {
		switch h.Kind {
		case config.HKHTTP:
			if h.Scheme == "" {
				h.Scheme = "https"
			}
			if h.Scheme == "http" {
				h.Port = 80
			} else {
				h.Port = 443
			}
		case config.HKTCP:
			h.Port = 443
		case config.HKUDP:
			h.Port = 53
		case config.HKICMP, config.HKRawIP:
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
	if h.Path == "" && (h.Kind == config.HKHTTP || h.Kind == config.HKHTTP3) {
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
		case config.HKHTTP:
			if h.Scheme == "http" {
				h.Port = 80
			} else {
				h.Port = 443
			}
		case config.HKHTTP3:
			h.Port = 443
		case config.HKTCP:
			h.Port = 443
		case config.HKUDP:
			h.Port = 53
		case config.HKICMP:
		}
	}
	return h
}

// ProbeAny probes the provided IPs using the given health configuration.
func ProbeAny(ctx context.Context, ips []string, hc config.HealthConfig) bool {
	for _, ip := range ips {
		p := net.ParseIP(ip)
		if p == nil {
			continue
		}
		var err error
		switch hc.Kind {
		case config.HKHTTP, "":
			err = httpCheck(ctx, ip, hc)
		case config.HKHTTP3:
			err = http3Check(ctx, ip, hc)
		case config.HKTCP:
			err = tcpCheck(ctx, ip, hc)
		case config.HKUDP:
			err = udpCheck(ctx, ip, hc)
		case config.HKICMP:
			err = icmpCheck(ctx, ip, hc)
		case config.HKRawIP:
			err = rawIPCheck(ctx, ip, hc)
		default:
			err = fmt.Errorf("unknown health kind %q", hc.Kind)
		}
		if err == nil {
			return true
		}
	}
	return false
}

func tcpCheck(ctx context.Context, ip string, h config.HealthConfig) error {
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

func udpCheck(ctx context.Context, ip string, h config.HealthConfig) error {
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
		buf := make([]byte, 4)
		uc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = uc.Read(buf)
		return nil
	}
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

func rawIPCheck(ctx context.Context, ip string, h config.HealthConfig) error {
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

func icmpCheck(ctx context.Context, ip string, h config.HealthConfig) error {
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
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: payload},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}
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
			}
			return 58
		}(), rb[:n])
		if err != nil {
			return err
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			return nil
		default:
		}
	}
}

func http3Check(ctx context.Context, ip string, hc config.HealthConfig) error {
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

func httpCheck(ctx context.Context, ip string, hc config.HealthConfig) error {
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

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
