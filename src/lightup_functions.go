package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func compileLightupSpecs(zones []Zone) []lightupRuntimeSpec {
	specs := make([]lightupRuntimeSpec, 0, len(zones))
	for _, z := range zones {
		spec, ok := compileLightupSpec(z)
		if !ok {
			continue
		}
		specs = append(specs, spec)
	}
	return specs
}

func compileLightupSpec(z Zone) (lightupRuntimeSpec, bool) {
	if z.Lightup == nil {
		return lightupRuntimeSpec{}, false
	}
	prefix, exclude, respondAAAA, respondPTR, ok := effectiveLightupFamily(z.Lightup)
	if !ok {
		return lightupRuntimeSpec{}, false
	}
	_, prefixNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return lightupRuntimeSpec{}, false
	}
	spec := lightupRuntimeSpec{
		zoneName:    ensureDot(z.Name),
		ptrTemplate: strings.TrimSpace(z.Lightup.PTRTemplate),
		ttl:         z.Lightup.TTL,
		prefix:      prefixNet,
		respondPTR:  respondPTR,
		respondAAAA: respondAAAA,
	}
	for _, raw := range exclude {
		_, exNet, err := net.ParseCIDR(raw)
		if err != nil {
			return lightupRuntimeSpec{}, false
		}
		spec.exclude = append(spec.exclude, exNet)
	}
	return spec, true
}

func effectiveLightupFamily(l *LightupConfig) (prefix string, exclude []string, respondAAAA, respondPTR, ok bool) {
	if l == nil || !l.Enabled {
		return "", nil, false, false, false
	}
	if len(l.Families) > 0 {
		fam := l.Families[0]
		prefix = strings.TrimSpace(fam.Prefix)
		exclude = append([]string(nil), fam.Exclude...)
		respondAAAA = fam.RespondAAAA
		respondPTR = fam.RespondPTR
	} else {
		prefix = strings.TrimSpace(l.Prefix)
		exclude = append([]string(nil), l.Exclude...)
	}
	if prefix == "" {
		return "", nil, false, false, false
	}
	if !respondAAAA && !respondPTR {
		if l.Forward || l.Reverse {
			respondAAAA = l.Forward
			respondPTR = l.Reverse
		} else {
			respondAAAA = true
			respondPTR = true
		}
	}
	return prefix, exclude, respondAAAA, respondPTR, true
}

func (a *authority) lightupPTRRecord(owner string) *dns.PTR {
	ip, ok := parseIPv6ReverseOwner(owner)
	if !ok {
		return nil
	}
	spec, ok := a.bestLightupPTRSpec(ip)
	if !ok {
		return nil
	}
	ttl := spec.ttl
	if ttl == 0 {
		ttl = a.zone.TTLAnswer
	}
	return &dns.PTR{
		Hdr: hdr(owner, dns.TypePTR, ttl),
		Ptr: ensureDot(lightupPTRTarget(spec, ip)),
	}
}

func (a *authority) bestLightupPTRSpec(ip net.IP) (lightupRuntimeSpec, bool) {
	var best lightupRuntimeSpec
	bestBits := -1
	for _, spec := range a.lightup {
		if !spec.respondPTR || spec.prefix == nil {
			continue
		}
		if !spec.prefix.Contains(ip) || lightupIPExcluded(ip, spec.exclude) {
			continue
		}
		ones, _ := spec.prefix.Mask.Size()
		if ones > bestBits {
			best = spec
			bestBits = ones
		}
	}
	return best, bestBits >= 0
}

func lightupIPExcluded(ip net.IP, exclude []*net.IPNet) bool {
	for _, ex := range exclude {
		if ex.Contains(ip) {
			return true
		}
	}
	return false
}

func lightupPTRTarget(spec lightupRuntimeSpec, ip net.IP) string {
	if spec.ptrTemplate != "" && strings.Contains(spec.ptrTemplate, "{addr}") {
		return strings.ReplaceAll(spec.ptrTemplate, "{addr}", lightupIPLabel(ip))
	}
	return "addr-" + lightupIPLabel(ip) + "." + strings.TrimSuffix(spec.zoneName, ".") + "."
}

func lightupIPLabel(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	parts := make([]string, 0, 8)
	for i := 0; i < 16; i += 2 {
		parts = append(parts, fmt.Sprintf("%02x%02x", ip[i], ip[i+1]))
	}
	return strings.Join(parts, "-")
}

func parseIPv6ReverseOwner(owner string) (net.IP, bool) {
	owner = strings.ToLower(ensureDot(owner))
	const suffix = ".ip6.arpa."
	if !strings.HasSuffix(owner, suffix) {
		return nil, false
	}
	trimmed := strings.TrimSuffix(owner, suffix)
	parts := strings.Split(trimmed, ".")
	if len(parts) != 32 {
		return nil, false
	}
	hexDigits := make([]byte, 32)
	for i, part := range parts {
		if len(part) != 1 || !strings.Contains("0123456789abcdef", part) {
			return nil, false
		}
		hexDigits[len(hexDigits)-1-i] = part[0]
	}
	buf := make([]byte, 16)
	if _, err := hex.Decode(buf, hexDigits); err != nil {
		return nil, false
	}
	return net.IP(buf), true
}

func (a *authority) runtimeNameTypes(name string) []uint16 {
	if rr := a.lightupPTRRecord(name); rr != nil {
		return []uint16{dns.TypePTR}
	}
	return nil
}

func (a *authority) runtimeTypeBitmap(name string) []uint16 {
	types := a.runtimeNameTypes(name)
	if len(types) == 0 {
		return nil
	}
	out := append([]uint16(nil), types...)
	if !hasRRType(out, dns.TypeRRSIG) {
		out = append(out, dns.TypeRRSIG)
	}
	if a.keys != nil && a.keys.nsec3Iterations > 0 {
		if !hasRRType(out, dns.TypeNSEC3) {
			out = append(out, dns.TypeNSEC3)
		}
	} else {
		if !hasRRType(out, dns.TypeNSEC) {
			out = append(out, dns.TypeNSEC)
		}
	}
	return out
}

func hasRRType(types []uint16, want uint16) bool {
	for _, typ := range types {
		if typ == want {
			return true
		}
	}
	return false
}
