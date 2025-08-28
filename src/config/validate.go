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
	if err := validatePersistenceMode(z.PersistenceMode); err != nil {
		return fmt.Errorf("persistence_mode: %w", err)
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

	// Geo answer overrides
	if z.GeoAnswers != nil {
		if err := ValidateGeoAnswers(z.GeoAnswers); err != nil {
			return err
		}
	}

	return nil
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
