package config

// record_validate.go provides preflight validation for YAML-specified records.
// Each check enforces basic RFC constraints (domain name length, text field size,
// and numeric ranges) so that malformed configuration is rejected before runtime.

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// validateConfig walks through the parsed configuration and validates every zone
// and record it contains.
func ValidateConfig(cfg *Config) error {
	if err := validatePersistenceMode(cfg.PersistenceMode); err != nil {
		return fmt.Errorf("persistence_mode: %w", err)
	}
	if cfg.API {
		if cfg.APIListen == 0 || cfg.APIToken == "" || cfg.APICert == "" || cfg.APIKey == "" {
			return fmt.Errorf("api enabled but api-listen, api-token, api-cert, and api-key must be set")
		}
	}
	l := cfg.Listen != ""
	la := len(cfg.ListenAddrs) > 0
	ifc := len(cfg.Interfaces) > 0
	if (l && la) || (l && ifc) || (la && ifc) {
		precedence := "listen"
		if la {
			precedence = "listen_addrs"
		} else if ifc {
			precedence = "interfaces"
		}
		return fmt.Errorf("only one of listen, listen_addrs, or interfaces may be set; %s takes precedence", precedence)
	}
	for i := range cfg.Zones {
		if err := ValidateZone(&cfg.Zones[i]); err != nil {
			return fmt.Errorf("zone %q: %w", cfg.Zones[i].Name, err)
		}
	}
	return nil
}

// ValidateZone performs basic sanity checks on a zone and its records.
func ValidateZone(z *Zone) error {
	if err := validateDomain(z.Name); err != nil {
		return err
	}
	if err := validateDomain(z.Admin); err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	for i, ns := range z.NS {
		if err := validateDomain(ns); err != nil {
			return fmt.Errorf("ns[%d]: %w", i, err)
		}
	}
	if z.Alias != "" {
		if err := validateDomain(z.Alias); err != nil {
			return fmt.Errorf("alias: %w", err)
		}
	}
	if z.XFRSource != "" {
		ip := net.ParseIP(strings.TrimSpace(z.XFRSource))
		if ip == nil {
			return fmt.Errorf("xfr_source: invalid IP %q", z.XFRSource)
		}
	}
	for h, tgt := range z.AliasHost {
		base := strings.TrimSuffix(z.Name, ".")
		if err := validateDomain(h + "." + base); err != nil {
			return fmt.Errorf("alias_host[%s]: %w", h, err)
		}
		if err := validateDomain(tgt); err != nil {
			return fmt.Errorf("alias_host[%s]: %w", h, err)
		}
	}
	if err := validatePersistenceMode(z.PersistenceMode); err != nil {
		return fmt.Errorf("persistence_mode: %w", err)
	}
	if err := validatePools(z.Pools); err != nil {
		return err
	}
	if err := validateHosts(z); err != nil {
		return err
	}
	if z.Geo != nil && len(z.Geo.Named) > 0 {
		poolNames := map[string]bool{}
		for _, p := range z.Pools {
			poolNames[strings.ToLower(strings.TrimSpace(p.Name))] = true
		}
		for _, gp := range z.Geo.Named {
			if !poolNames[strings.ToLower(strings.TrimSpace(gp.Name))] {
				return fmt.Errorf("geo[%s]: unknown pool", gp.Name)
			}
		}
	}

	const maxSOA = 2147483647
	if z.Refresh == 0 || z.Refresh > maxSOA {
		return fmt.Errorf("refresh must be 1..%d", maxSOA)
	}
	if z.Retry == 0 || z.Retry > maxSOA {
		return fmt.Errorf("retry must be 1..%d", maxSOA)
	}
	if z.Expire == 0 || z.Expire > maxSOA {
		return fmt.Errorf("expire must be 1..%d", maxSOA)
	}
	if z.Minttl == 0 || z.Minttl > maxSOA {
		return fmt.Errorf("minttl must be 1..%d", maxSOA)
	}

	// Validate core A/AAAA lists
	if err := ValidateIPAddrList(z.AMaster, false, "a_master"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AAAAMaster, true, "aaaa_master"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AStandby, false, "a_standby"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AAAAStandby, true, "aaaa_standby"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AFallback, false, "a_fallback"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AAAAFallback, true, "aaaa_fallback"); err != nil {
		return err
	}

	// Per-tier private answers
	if err := ValidateIPAddrList(z.AMasterPrivate, false, "a_master_private"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AAAAMasterPrivate, true, "aaaa_master_private"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AStandbyPrivate, false, "a_standby_private"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AAAAStandbyPrivate, true, "aaaa_standby_private"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AFallbackPrivate, false, "a_fallback_private"); err != nil {
		return err
	}
	if err := ValidateIPAddrList(z.AAAAFallbackPrivate, true, "aaaa_fallback_private"); err != nil {
		return err
	}

	// Shared/static records
	for i := range z.TXT {
		if err := validateTXTRecord(&z.TXT[i]); err != nil {
			return fmt.Errorf("txt[%d]: %w", i, err)
		}
	}
	for i := range z.MX {
		if err := validateMXRecord(&z.MX[i]); err != nil {
			return fmt.Errorf("mx[%d]: %w", i, err)
		}
	}
	for i := range z.CAA {
		if err := validateCAARecord(&z.CAA[i]); err != nil {
			return fmt.Errorf("caa[%d]: %w", i, err)
		}
	}
	if z.RP != nil {
		if err := validateRPRecord(z.RP); err != nil {
			return fmt.Errorf("rp: %w", err)
		}
	}
	for i := range z.SSHFP {
		if err := validateSSHFPRecord(&z.SSHFP[i]); err != nil {
			return fmt.Errorf("sshfp[%d]: %w", i, err)
		}
	}
	for i := range z.SRV {
		if err := validateSRVRecord(&z.SRV[i]); err != nil {
			return fmt.Errorf("srv[%d]: %w", i, err)
		}
	}
	for i := range z.NAPTR {
		if err := validateNAPTRRecord(&z.NAPTR[i]); err != nil {
			return fmt.Errorf("naptr[%d]: %w", i, err)
		}
	}
	for i := range z.PTR {
		if err := validatePTRRecord(&z.PTR[i]); err != nil {
			return fmt.Errorf("ptr[%d]: %w", i, err)
		}
	}

	// Geo answer overrides
	if z.GeoAnswers != nil {
		if err := ValidateGeoAnswers(z.GeoAnswers); err != nil {
			return err
		}
	}
	if z.Lightup != nil {
		if err := validateLightup(z.Lightup); err != nil {
			return fmt.Errorf("lightup: %w", err)
		}
	}
	if z.TSIG != nil {
		for i, k := range z.TSIG.Keys {
			for j, raw := range k.AllowXFRFrom {
				if !validateAllowXFRFrom(strings.TrimSpace(raw)) {
					return fmt.Errorf("tsig.keys[%d].allow_xfr_from[%d]: invalid IP or CIDR %q", i, j, raw)
				}
			}
		}
	}

	return nil
}

func validatePools(pools []Pool) error {
	for i, p := range pools {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("pools[%d].name is required", i)
		}
		family := strings.ToLower(strings.TrimSpace(p.Family))
		if family != "ipv4" && family != "ipv6" {
			return fmt.Errorf("pools[%d].family: unsupported value %q", i, p.Family)
		}
		class := strings.ToLower(strings.TrimSpace(p.Class))
		if class != "" && class != "public" && class != "private" {
			return fmt.Errorf("pools[%d].class: unsupported value %q", i, p.Class)
		}
		if len(p.Members) == 0 {
			return fmt.Errorf("pools[%d].members is required", i)
		}
		if err := ValidateIPAddrList(p.Members, family == "ipv6", fmt.Sprintf("pools[%d].members", i)); err != nil {
			return err
		}
		for j, raw := range p.ClientNets {
			_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
			if err != nil {
				return fmt.Errorf("pools[%d].client_nets[%d]: invalid CIDR %q", i, j, raw)
			}
			if family == "ipv4" {
				if n.IP.To4() == nil {
					return fmt.Errorf("pools[%d].client_nets[%d]: %q is not IPv4", i, j, raw)
				}
			} else if n.IP.To4() != nil {
				return fmt.Errorf("pools[%d].client_nets[%d]: %q is not IPv6", i, j, raw)
			}
		}
	}
	return nil
}

func validateHosts(z *Zone) error {
	seen := map[string]bool{}
	for i, h := range z.Hosts {
		owner, err := validateHostName(z.Name, h.Name)
		if err != nil {
			return fmt.Errorf("hosts[%d].name: %w", i, err)
		}
		key := strings.ToLower(owner)
		if seen[key] {
			return fmt.Errorf("hosts[%d].name: duplicate host %q", i, h.Name)
		}
		seen[key] = true
		if h.Alias != "" {
			if err := validateDomain(h.Alias); err != nil {
				return fmt.Errorf("hosts[%d].alias: %w", i, err)
			}
		}
		if err := validatePools(h.Pools); err != nil {
			return fmt.Errorf("hosts[%d]: %w", i, err)
		}
		if h.Geo != nil && len(h.Geo.Named) > 0 {
			poolNames := map[string]bool{}
			for _, p := range h.Pools {
				poolNames[strings.ToLower(strings.TrimSpace(p.Name))] = true
			}
			for _, gp := range h.Geo.Named {
				if !poolNames[strings.ToLower(strings.TrimSpace(gp.Name))] {
					return fmt.Errorf("hosts[%d].geo[%s]: unknown pool", i, gp.Name)
				}
			}
		}
	}
	return nil
}

func validateHostName(apex, name string) (string, error) {
	name = strings.TrimSpace(name)
	switch name {
	case "", ".", "@":
		return EnsureDot(apex), nil
	}
	base := strings.TrimSuffix(EnsureDot(apex), ".")
	if strings.Contains(name, ".") {
		fqdn := EnsureDot(name)
		if err := validateDomain(fqdn); err != nil {
			return "", err
		}
		if !strings.HasSuffix(strings.ToLower(fqdn), "."+strings.ToLower(base)+".") && strings.ToLower(fqdn) != strings.ToLower(EnsureDot(apex)) {
			return "", fmt.Errorf("%q is outside zone %q", name, apex)
		}
		return fqdn, nil
	}
	fqdn := EnsureDot(name + "." + base)
	if err := validateDomain(fqdn); err != nil {
		return "", err
	}
	return fqdn, nil
}

func validateLightup(l *LightupConfig) error {
	if l == nil {
		return nil
	}
	if !l.Enabled &&
		strings.TrimSpace(l.Domain) == "" &&
		l.TTL == 0 &&
		!l.Forward &&
		!l.Reverse &&
		strings.TrimSpace(l.Strategy) == "" &&
		strings.TrimSpace(l.Prefix) == "" &&
		len(l.Exclude) == 0 &&
		len(l.Families) == 0 &&
		strings.TrimSpace(l.ForwardTemplate) == "" &&
		strings.TrimSpace(l.PTRTemplate) == "" &&
		len(l.NSAAAA) == 0 {
		return nil
	}
	if l.Domain != "" {
		if err := validateDomain(l.Domain); err != nil {
			return fmt.Errorf("domain: %w", err)
		}
	}
	if l.Strategy != "" && l.Strategy != "hash" {
		return fmt.Errorf("strategy: unsupported value %q", l.Strategy)
	}
	for i, raw := range l.NSAAAA {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To16() == nil || ip.To4() != nil {
			return fmt.Errorf("ns_aaaa[%d]: %q is not IPv6", i, raw)
		}
	}
	if len(l.Families) > 0 && (strings.TrimSpace(l.Prefix) != "" || len(l.Exclude) > 0) {
		return fmt.Errorf("legacy prefix/exclude cannot be combined with families")
	}
	if len(l.Families) > 0 {
		for i, fam := range l.Families {
			if fam.Family != "" && fam.Family != "ipv6" && fam.Family != "ipv4" {
				return fmt.Errorf("families[%d].family: unsupported value %q", i, fam.Family)
			}
			switch fam.Family {
			case "ipv4":
				if fam.Class != "" && fam.Class != "public" && fam.Class != "private" {
					return fmt.Errorf("families[%d].class: unsupported value %q", i, fam.Class)
				}
			default:
				if fam.Class != "" && fam.Class != "public" && fam.Class != "ula" {
					return fmt.Errorf("families[%d].class: unsupported value %q", i, fam.Class)
				}
			}
			if fam.RespondA && fam.Family == "ipv6" {
				return fmt.Errorf("families[%d].respond_a: only valid for ipv4 families", i)
			}
			if fam.RespondAAAA && fam.Family == "ipv4" {
				return fmt.Errorf("families[%d].respond_aaaa: only valid for ipv6 families", i)
			}
			if err := validateLightupPrefixAndExcludes(
				fam.Family,
				fmt.Sprintf("families[%d].prefix", i),
				fam.Prefix,
				fam.Exclude,
				fmt.Sprintf("families[%d].exclude", i),
			); err != nil {
				return err
			}
		}
		return nil
	}
	return validateLightupPrefixAndExcludes("ipv6", "prefix", l.Prefix, l.Exclude, "exclude")
}

func validateLightupPrefixAndExcludes(family, prefixField, prefix string, exclude []string, excludeField string) error {
	if strings.TrimSpace(prefix) == "" {
		return fmt.Errorf("%s is required", prefixField)
	}
	_, prefixNet, err := net.ParseCIDR(strings.TrimSpace(prefix))
	if err != nil {
		return fmt.Errorf("%s: invalid CIDR %q", prefixField, prefix)
	}
	wantIPv4 := strings.EqualFold(strings.TrimSpace(family), "ipv4")
	if wantIPv4 {
		if prefixNet.IP.To4() == nil {
			return fmt.Errorf("%s: %q is not IPv4", prefixField, prefix)
		}
	} else if prefixNet.IP.To4() != nil {
		return fmt.Errorf("%s: %q is not IPv6", prefixField, prefix)
	}
	prefixOnes, _ := prefixNet.Mask.Size()
	seen := make([]*net.IPNet, 0, len(exclude))
	for i, raw := range exclude {
		_, exNet, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s[%d]: invalid CIDR %q", excludeField, i, raw)
		}
		if wantIPv4 {
			if exNet.IP.To4() == nil {
				return fmt.Errorf("%s[%d]: %q is not IPv4", excludeField, i, raw)
			}
		} else if exNet.IP.To4() != nil {
			return fmt.Errorf("%s[%d]: %q is not IPv6", excludeField, i, raw)
		}
		exOnes, _ := exNet.Mask.Size()
		if exOnes < prefixOnes || !prefixNet.Contains(exNet.IP) {
			return fmt.Errorf("%s[%d]: %q is outside prefix %q", excludeField, i, raw, prefix)
		}
		for j, prev := range seen {
			if cidrOverlap(prev, exNet) {
				return fmt.Errorf("%s[%d]: %q overlaps %s[%d] %q", excludeField, i, raw, excludeField, j, exclude[j])
			}
		}
		seen = append(seen, exNet)
	}
	return nil
}

func cidrOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func validateAllowXFRFrom(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if strings.Contains(raw, "/") {
		_, _, err := net.ParseCIDR(raw)
		return err == nil
	}
	return net.ParseIP(raw) != nil
}

func validatePersistenceMode(m string) error {
	switch strings.ToLower(m) {
	case "", "rr", "wrr", "random":
		return nil
	default:
		return fmt.Errorf("invalid mode %q", m)
	}
}

// validateDomain ensures a domain name is valid and within RFC limits.
func validateDomain(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty domain name")
	}
	fqdn := EnsureDot(name)
	if !dns.IsFqdn(fqdn) {
		return fmt.Errorf("invalid domain %q", name)
	}
	if len(fqdn) > 255 {
		return fmt.Errorf("domain %q exceeds 255 characters", name)
	}
	for _, label := range dns.SplitDomainName(fqdn) {
		if len(label) > 63 {
			return fmt.Errorf("label %q in %q exceeds 63 characters", label, name)
		}
	}
	return nil
}

// ValidateIPList checks that every string is a valid IPv4 or IPv6 address.
func ValidateIPList(list []string, ipv6 bool, field string) error {
	for i, s := range list {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return fmt.Errorf("%s[%d]: invalid IP %q", field, i, s)
		}
		if ipv6 {
			if ip.To16() == nil || ip.To4() != nil {
				return fmt.Errorf("%s[%d]: %q is not IPv6", field, i, s)
			}
		} else {
			if ip.To4() == nil {
				return fmt.Errorf("%s[%d]: %q is not IPv4", field, i, s)
			}
		}
	}
	return nil
}

// ValidateIPAddrList checks IPAddr slices.
func ValidateIPAddrList(list []IPAddr, ipv6 bool, field string) error {
	for i, s := range list {
		ip := net.ParseIP(strings.TrimSpace(s.IP))
		if ip == nil {
			return fmt.Errorf("%s[%d]: invalid IP %q", field, i, s.IP)
		}
		if ipv6 {
			if ip.To16() == nil || ip.To4() != nil {
				return fmt.Errorf("%s[%d]: %q is not IPv6", field, i, s.IP)
			}
		} else {
			if ip.To4() == nil {
				return fmt.Errorf("%s[%d]: %q is not IPv4", field, i, s.IP)
			}
		}
	}
	return nil
}

func validateTXTRecord(r *TXTRecord) error {
	if r.Name != "" {
		if err := validateDomain(r.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	for i, txt := range r.Text {
		if len(txt) > 255 {
			return fmt.Errorf("text[%d] exceeds 255 bytes", i)
		}
	}
	return nil
}

func validateMXRecord(r *MXRecord) error {
	if r.Name != "" {
		if err := validateDomain(r.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	if err := validateDomain(r.Exchange); err != nil {
		return fmt.Errorf("exchange: %w", err)
	}
	return nil
}

func validateCAARecord(r *CAARecord) error {
	if r.Name != "" {
		if err := validateDomain(r.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	if len(r.Tag) > 255 {
		return fmt.Errorf("tag exceeds 255 bytes")
	}
	if len(r.Value) > 255 {
		return fmt.Errorf("value exceeds 255 bytes")
	}
	return nil
}

func validateRPRecord(r *RPRecord) error {
	if r.Name != "" {
		if err := validateDomain(r.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	if err := validateDomain(r.Mbox); err != nil {
		return fmt.Errorf("mbox: %w", err)
	}
	if err := validateDomain(r.Txt); err != nil {
		return fmt.Errorf("txt: %w", err)
	}
	return nil
}

func validateSSHFPRecord(r *SSHFPRecord) error {
	if r.Name != "" {
		if err := validateDomain(r.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	if _, err := hex.DecodeString(strings.TrimSpace(r.Fingerprint)); err != nil {
		return fmt.Errorf("fingerprint: %v", err)
	}
	return nil
}

func validateSRVRecord(r *SRVRecord) error {
	if err := validateDomain(r.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if err := validateDomain(r.Target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	return nil
}

func validateNAPTRRecord(r *NAPTRRecord) error {
	if err := validateDomain(r.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if len(r.Flags) > 255 {
		return fmt.Errorf("flags exceeds 255 bytes")
	}
	if len(r.Services) > 255 {
		return fmt.Errorf("services exceeds 255 bytes")
	}
	if len(r.Regexp) > 255 {
		return fmt.Errorf("regexp exceeds 255 bytes")
	}
	if err := validateDomain(r.Replacement); err != nil {
		return fmt.Errorf("replacement: %w", err)
	}
	return nil
}

func validatePTRRecord(r *PTRRecord) error {
	if r.Name != "" && r.Name != "." && r.Name != "@" {
		if err := validateDomain(r.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	if err := validateDomain(r.PTR); err != nil {
		return fmt.Errorf("ptr: %w", err)
	}
	return nil
}

func ValidateGeoAnswers(g *GeoAnswers) error {
	for c, set := range g.Country {
		if err := ValidateGeoAnswerSet(set, fmt.Sprintf("geo_answers.country[%s]", c)); err != nil {
			return err
		}
	}
	for c, set := range g.Continent {
		if err := ValidateGeoAnswerSet(set, fmt.Sprintf("geo_answers.continent[%s]", c)); err != nil {
			return err
		}
	}
	return nil
}

func ValidateGeoAnswerSet(set GeoAnswerSet, prefix string) error {
	if err := ValidateIPList(set.A, false, prefix+".a"); err != nil {
		return err
	}
	if err := ValidateIPList(set.AAAA, true, prefix+".aaaa"); err != nil {
		return err
	}
	if err := ValidateIPList(set.APrivate, false, prefix+".a_private"); err != nil {
		return err
	}
	if err := ValidateIPList(set.AAAAPrivate, true, prefix+".aaaa_private"); err != nil {
		return err
	}
	if err := ValidateIPList(set.RFC, false, prefix+".rfc"); err != nil {
		return err
	}
	if err := ValidateIPList(set.ULA, true, prefix+".ula"); err != nil {
		return err
	}
	return nil
}
