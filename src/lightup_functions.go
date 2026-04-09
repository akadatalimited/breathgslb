package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func compileLightupSpecs(zones []Zone) []lightupRuntimeSpec {
	specs := make([]lightupRuntimeSpec, 0, len(zones))
	for _, z := range zones {
		zoneSpecs := compileLightupSpec(z)
		if len(zoneSpecs) == 0 {
			continue
		}
		specs = append(specs, zoneSpecs...)
	}
	return specs
}

func compileLightupSpec(z Zone) []lightupRuntimeSpec {
	if z.Lightup == nil {
		return nil
	}
	zoneName := ensureDot(z.Name)
	if strings.TrimSpace(z.Lightup.Domain) != "" {
		zoneName = ensureDot(z.Lightup.Domain)
	}
	families := effectiveLightupFamilies(z.Lightup)
	specs := make([]lightupRuntimeSpec, 0, len(families))
	for _, fam := range families {
		_, prefixNet, err := net.ParseCIDR(fam.prefix)
		if err != nil {
			return nil
		}
		spec := lightupRuntimeSpec{
			zoneName:    zoneName,
			class:       fam.class,
			forwardTmpl: strings.TrimSpace(z.Lightup.ForwardTemplate),
			ptrTemplate: strings.TrimSpace(z.Lightup.PTRTemplate),
			ttl:         z.Lightup.TTL,
			prefix:      prefixNet,
			respondPTR:  fam.respondPTR,
			respondAAAA: fam.respondAAAA,
		}
		for _, raw := range fam.exclude {
			_, exNet, err := net.ParseCIDR(raw)
			if err != nil {
				return nil
			}
			spec.exclude = append(spec.exclude, exNet)
		}
		specs = append(specs, spec)
	}
	return specs
}

type lightupFamilyConfig struct {
	class       string
	prefix      string
	exclude     []string
	respondAAAA bool
	respondPTR  bool
}

func effectiveLightupFamilies(l *LightupConfig) []lightupFamilyConfig {
	if l == nil || !l.Enabled {
		return nil
	}
	var out []lightupFamilyConfig
	if len(l.Families) > 0 {
		for _, fam := range l.Families {
			cfg := lightupFamilyConfig{
				class:       strings.ToLower(strings.TrimSpace(fam.Class)),
				prefix:      strings.TrimSpace(fam.Prefix),
				exclude:     append([]string(nil), fam.Exclude...),
				respondAAAA: fam.RespondAAAA,
				respondPTR:  fam.RespondPTR,
			}
			if cfg.prefix == "" {
				continue
			}
			if !cfg.respondAAAA && !cfg.respondPTR {
				if l.Forward || l.Reverse {
					cfg.respondAAAA = l.Forward
					cfg.respondPTR = l.Reverse
				} else {
					cfg.respondAAAA = true
					cfg.respondPTR = true
				}
			}
			out = append(out, cfg)
		}
	} else {
		cfg := lightupFamilyConfig{
			prefix:      strings.TrimSpace(l.Prefix),
			exclude:     append([]string(nil), l.Exclude...),
			respondAAAA: l.Forward,
			respondPTR:  l.Reverse,
		}
		if cfg.prefix != "" {
			if !cfg.respondAAAA && !cfg.respondPTR {
				cfg.respondAAAA = true
				cfg.respondPTR = true
			}
			out = append(out, cfg)
		}
	}
	return out
}

func (a *authority) lightupAAAARecords(owner string, src net.IP) []dns.RR {
	if spec, ip, matched := a.exactLightupAAAA(owner); matched {
		if ip == nil {
			return nil
		}
		ttl := spec.ttl
		if ttl == 0 {
			ttl = a.zone.TTLAnswer
		}
		return buildAAAAForOwner(owner, ttl, []string{ip.String()}, a.cfg.MaxRecords, a.cfg.EDNSBuf)
	}
	spec, ok := a.bestLightupAAAASpec(owner, src)
	if !ok {
		return nil
	}
	ip := lightupHashedAddressForName(spec, owner)
	if ip == nil {
		return nil
	}
	ttl := spec.ttl
	if ttl == 0 {
		ttl = a.zone.TTLAnswer
	}
	return buildAAAAForOwner(owner, ttl, []string{ip.String()}, a.cfg.MaxRecords, a.cfg.EDNSBuf)
}

func (a *authority) exactLightupAAAA(owner string) (lightupRuntimeSpec, net.IP, bool) {
	owner = strings.ToLower(ensureDot(owner))
	matched := false
	for _, spec := range a.lightup {
		if !spec.respondAAAA {
			continue
		}
		ip, ok := lightupExactAddressForName(spec, owner)
		if !ok {
			continue
		}
		matched = true
		if ip == nil {
			continue
		}
		if spec.prefix == nil || !spec.prefix.Contains(ip) || lightupIPExcluded(ip, spec.exclude) {
			continue
		}
		return spec, ip, true
	}
	return lightupRuntimeSpec{}, nil, matched
}

func (a *authority) bestLightupAAAASpec(owner string, src net.IP) (lightupRuntimeSpec, bool) {
	owner = strings.ToLower(ensureDot(owner))
	preferredClass := lightupPreferredClass(src)
	var preferred []lightupRuntimeSpec
	var fallback []lightupRuntimeSpec
	for _, spec := range a.lightup {
		if !spec.respondAAAA || !strings.EqualFold(spec.zoneName, a.zone.Name) {
			continue
		}
		if !a.lightupNameAllowed(owner, spec.zoneName) {
			continue
		}
		if spec.class == preferredClass || (preferredClass == "public" && spec.class == "") {
			preferred = append(preferred, spec)
		} else {
			fallback = append(fallback, spec)
		}
	}
	if len(preferred) > 0 {
		return preferred[0], true
	}
	if len(fallback) > 0 {
		return fallback[0], true
	}
	return lightupRuntimeSpec{}, false
}

func (a *authority) lightupNameAllowed(owner, zoneName string) bool {
	owner = strings.ToLower(ensureDot(owner))
	zoneName = strings.ToLower(ensureDot(zoneName))
	if !strings.HasSuffix(owner, zoneName) {
		return false
	}
	if a.zidx != nil && a.zidx.hasName(owner) {
		return false
	}
	return owner != zoneName
}

func lightupPreferredClass(src net.IP) string {
	if isRFC1918OrULA(src) {
		return "ula"
	}
	return "public"
}

func isRFC1918OrULA(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1]&0xf0 == 16:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		default:
			return false
		}
	}
	ip = ip.To16()
	return ip != nil && (ip[0]&0xfe) == 0xfc
}

func lightupHashedAddressForName(spec lightupRuntimeSpec, name string) net.IP {
	if spec.prefix == nil {
		return nil
	}
	base := spec.prefix.IP.Mask(spec.prefix.Mask).To16()
	if base == nil {
		return nil
	}
	for attempt := 0; attempt < 256; attempt++ {
		candidate := append(net.IP(nil), base...)
		hash := lightupHash128(name, 0)
		applyLightupHostBits(candidate, spec.prefix.Mask, hash[:])
		addLightupHostOffset(candidate, spec.prefix.Mask, attempt)
		if spec.prefix.Contains(candidate) && !lightupIPExcluded(candidate, spec.exclude) {
			return candidate
		}
	}
	return nil
}

func lightupAddressForName(spec lightupRuntimeSpec, name string) net.IP {
	return lightupHashedAddressForName(spec, name)
}

func lightupExactAddressForName(spec lightupRuntimeSpec, owner string) (net.IP, bool) {
	template := lightupForwardTemplate(spec)
	prefix, suffix, ok := strings.Cut(strings.ToLower(template), "{addr}")
	if !ok {
		return nil, false
	}
	owner = strings.ToLower(ensureDot(owner))
	if !strings.HasPrefix(owner, prefix) || !strings.HasSuffix(owner, suffix) {
		return nil, false
	}
	embedded := owner[len(prefix) : len(owner)-len(suffix)]
	ip, ok := parseLightupAddrLabel(embedded)
	if !ok {
		return nil, true
	}
	return ip, true
}

func lightupForwardTemplate(spec lightupRuntimeSpec) string {
	if spec.forwardTmpl != "" && strings.Contains(spec.forwardTmpl, "{addr}") {
		return ensureDot(spec.forwardTmpl)
	}
	return ensureDot("addr-{addr}." + strings.TrimSuffix(spec.zoneName, "."))
}

func parseLightupAddrLabel(label string) (net.IP, bool) {
	parts := strings.Split(strings.TrimSpace(strings.ToLower(label)), "-")
	if len(parts) != 8 {
		return nil, false
	}
	for _, part := range parts {
		if len(part) != 4 {
			return nil, false
		}
		for _, ch := range part {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return nil, false
			}
		}
	}
	ip := net.ParseIP(strings.Join(parts, ":"))
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return nil, false
	}
	return ip.To16(), true
}

func lightupHash128(name string, counter byte) [16]byte {
	owner := []byte(strings.ToLower(ensureDot(name)))
	var out [16]byte
	for i := 0; i < 2; i++ {
		h := fnv.New64a()
		_, _ = h.Write(owner)
		_, _ = h.Write([]byte{counter, byte(i)})
		binary.BigEndian.PutUint64(out[i*8:], h.Sum64())
	}
	return out
}

func applyLightupHostBits(ip net.IP, mask net.IPMask, bits []byte) {
	ones, _ := mask.Size()
	for bit := ones; bit < 128; bit++ {
		srcBit := bit - ones
		byteIdx := srcBit / 8
		bitIdx := 7 - (srcBit % 8)
		if byteIdx >= len(bits) {
			break
		}
		dstByte := bit / 8
		dstBit := 7 - (bit % 8)
		if ((bits[byteIdx] >> bitIdx) & 1) == 1 {
			ip[dstByte] |= 1 << dstBit
		}
	}
}

func addLightupHostOffset(ip net.IP, mask net.IPMask, offset int) {
	if offset <= 0 {
		return
	}
	ones, _ := mask.Size()
	for ; offset > 0; offset-- {
		carry := byte(1)
		for bit := 127; bit >= ones && carry == 1; bit-- {
			dstByte := bit / 8
			dstBit := 7 - (bit % 8)
			maskBit := byte(1 << dstBit)
			if ip[dstByte]&maskBit == 0 {
				ip[dstByte] |= maskBit
				carry = 0
			} else {
				ip[dstByte] &^= maskBit
			}
		}
	}
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
	if strings.Contains(lightupForwardTemplate(spec), "{addr}") {
		return strings.ReplaceAll(lightupForwardTemplate(spec), "{addr}", lightupIPLabel(ip))
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
	if rr := a.lightupAAAARecords(name, nil); len(rr) > 0 {
		return []uint16{dns.TypeAAAA}
	}
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

func removeRRType(types []uint16, want uint16) []uint16 {
	out := types[:0]
	for _, typ := range types {
		if typ != want {
			out = append(out, typ)
		}
	}
	return out
}
