package main

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
func validateConfig(cfg *Config) error {
	for i := range cfg.Zones {
		if err := validateZone(&cfg.Zones[i]); err != nil {
			return fmt.Errorf("zone %q: %w", cfg.Zones[i].Name, err)
		}
	}
	return nil
}

// validateZone performs basic sanity checks on a zone and its records.
func validateZone(z *Zone) error {
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

	// Validate core A/AAAA lists
	if err := validateIPList(z.AMaster, false, "a_master"); err != nil {
		return err
	}
	if err := validateIPList(z.AAAAMaster, true, "aaaa_master"); err != nil {
		return err
	}
	if err := validateIPList(z.AStandby, false, "a_standby"); err != nil {
		return err
	}
	if err := validateIPList(z.AAAAStandby, true, "aaaa_standby"); err != nil {
		return err
	}
	if err := validateIPList(z.AFallback, false, "a_fallback"); err != nil {
		return err
	}
	if err := validateIPList(z.AAAAFallback, true, "aaaa_fallback"); err != nil {
		return err
	}

	// Per-tier private answers
	if err := validateIPList(z.AMasterPrivate, false, "a_master_private"); err != nil {
		return err
	}
	if err := validateIPList(z.AAAAMasterPrivate, true, "aaaa_master_private"); err != nil {
		return err
	}
	if err := validateIPList(z.AStandbyPrivate, false, "a_standby_private"); err != nil {
		return err
	}
	if err := validateIPList(z.AAAAStandbyPrivate, true, "aaaa_standby_private"); err != nil {
		return err
	}
	if err := validateIPList(z.AFallbackPrivate, false, "a_fallback_private"); err != nil {
		return err
	}
	if err := validateIPList(z.AAAAFallbackPrivate, true, "aaaa_fallback_private"); err != nil {
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
		if err := validateGeoAnswers(z.GeoAnswers); err != nil {
			return err
		}
	}

	return nil
}

// validateDomain ensures a domain name is valid and within RFC limits.
func validateDomain(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty domain name")
	}
	fqdn := ensureDot(name)
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

// validateIPList checks that every string is a valid IPv4 or IPv6 address.
func validateIPList(list []string, ipv6 bool, field string) error {
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

func validateGeoAnswers(g *GeoAnswers) error {
	for c, set := range g.Country {
		if err := validateGeoAnswerSet(set, fmt.Sprintf("geo_answers.country[%s]", c)); err != nil {
			return err
		}
	}
	for c, set := range g.Continent {
		if err := validateGeoAnswerSet(set, fmt.Sprintf("geo_answers.continent[%s]", c)); err != nil {
			return err
		}
	}
	return nil
}

func validateGeoAnswerSet(set GeoAnswerSet, prefix string) error {
	if err := validateIPList(set.A, false, prefix+".a"); err != nil {
		return err
	}
	if err := validateIPList(set.AAAA, true, prefix+".aaaa"); err != nil {
		return err
	}
	if err := validateIPList(set.APrivate, false, prefix+".a_private"); err != nil {
		return err
	}
	if err := validateIPList(set.AAAAPrivate, true, prefix+".aaaa_private"); err != nil {
		return err
	}
	if err := validateIPList(set.RFC, false, prefix+".rfc"); err != nil {
		return err
	}
	if err := validateIPList(set.ULA, true, prefix+".ula"); err != nil {
		return err
	}
	return nil
}
