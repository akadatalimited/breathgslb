package main

import (
	"crypto"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSSEC functions

// loadDNSSEC loads DNSSEC keys for a zone.
func loadDNSSEC(z config.Zone) *DnssecKeys {
	if z.DNSSEC == nil || z.DNSSEC.Mode == DNSSECModeOff {
		return nil
	}
	k := &DnssecKeys{enabled: true}
	switch z.DNSSEC.Mode {
	case DNSSECModeManual:
		if z.DNSSEC.ZSKFile == "" {
			return nil
		}
		zsk, zskPriv, err := loadKeyPair(z.DNSSEC.ZSKFile)
		if err != nil {
			log.Printf("dnssec: load zsk %s failed: %v", z.DNSSEC.ZSKFile, err)
			return nil
		}
		k.zsk = zsk
		k.zskPriv = zskPriv
		if z.DNSSEC.KSKFile != "" && z.DNSSEC.KSKFile != z.DNSSEC.ZSKFile {
			ksk, kskPriv, err := loadKeyPair(z.DNSSEC.KSKFile)
			if err != nil {
				log.Printf("dnssec: load ksk %s failed: %v", z.DNSSEC.KSKFile, err)
				return nil
			}
			k.ksk = ksk
			k.kskPriv = kskPriv
		} else {
			k.ksk = zsk
			k.kskPriv = zskPriv
		}
	case DNSSECModeGenerated:
		fallthrough
	default:
		// Generate keys in memory or load from disk
		prefix := "K" + strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(z.Name, ".")), ".")
		if z.DNSSEC.Location == "disk" && z.DNSSEC.Path != "" {
			_ = os.MkdirAll(z.DNSSEC.Path, 0755)
			zskPath := filepath.Join(z.DNSSEC.Path, prefix+".zsk")
			kskPath := filepath.Join(z.DNSSEC.Path, prefix+".ksk")
			if z.DNSSEC.ZSKFile != "" {
				zskPath = z.DNSSEC.ZSKFile
			}
			if z.DNSSEC.KSKFile != "" {
				kskPath = z.DNSSEC.KSKFile
			}
			// Try to load existing keys
			zsk, zskPriv, err := loadKeyPair(zskPath)
			if err == nil {
				k.zsk = zsk
				k.zskPriv = zskPriv
			} else {
				// Generate new ZSK
				k.zsk, k.zskPriv = generateKeyPair(dns.ECDSAP256SHA256)
				if err := writeKeyPair(zskPath, k.zsk, k.zskPriv); err != nil {
					log.Printf("dnssec: write zsk %s failed: %v", zskPath, err)
				}
			}
			if kskPath != zskPath {
				ksk, kskPriv, err := loadKeyPair(kskPath)
				if err == nil {
					k.ksk = ksk
					k.kskPriv = kskPriv
				} else {
					// Generate new KSK
					k.ksk, k.kskPriv = generateKeyPair(dns.ECDSAP256SHA256)
					if err := writeKeyPair(kskPath, k.ksk, k.kskPriv); err != nil {
						log.Printf("dnssec: write ksk %s failed: %v", kskPath, err)
					}
				}
			} else {
				k.ksk = k.zsk
				k.kskPriv = k.zskPriv
			}
		} else {
			// Generate keys in memory only
			k.zsk, k.zskPriv = generateKeyPair(dns.ECDSAP256SHA256)
			k.ksk = k.zsk
			k.kskPriv = k.zskPriv
		}
	}
	// Set NSEC3 parameters if any
	if z.DNSSEC.NSEC3Iterations > 0 {
		k.nsec3Iterations = z.DNSSEC.NSEC3Iterations
		k.nsec3Salt = z.DNSSEC.NSEC3Salt
		k.nsec3OptOut = z.DNSSEC.NSEC3OptOut
	}
	return k
}

// loadKeyPair loads a DNSKEY pair from files.
func loadKeyPair(prefix string) (*dns.DNSKEY, crypto.Signer, error) {
	pubPath := prefix
	privPath := prefix
	if !strings.HasSuffix(pubPath, ".key") {
		pubPath += ".key"
	}
	if !strings.HasSuffix(privPath, ".private") {
		privPath += ".private"
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, err
	}
	priv, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, err
	}
	k, err := dns.NewDNSKEYFromRR(pub)
	if err != nil {
		return nil, nil, err
	}
	p, err := k.ReadPrivateKey(strings.NewReader(string(priv)), "")
	if err != nil {
		return nil, nil, err
	}
	s, ok := p.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not a crypto.Signer")
	}
	return k, s, nil
}

// generateKeyPair generates a new DNSKEY pair.
func generateKeyPair(alg uint8) (*dns.DNSKEY, crypto.Signer) {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 0},
		Flags:     257, // KSK
		Protocol:  3,
		Algorithm: alg,
	}
	priv, err := k.Generate(alg)
	if err != nil {
		log.Printf("dnssec: generate key failed: %v", err)
		return nil, nil
	}
	s, ok := priv.(crypto.Signer)
	if !ok {
		log.Printf("dnssec: generated private key is not a crypto.Signer")
		return nil, nil
	}
	return k, s
}

// writeKeyPair writes a DNSKEY pair to files.
func writeKeyPair(prefix string, key *dns.DNSKEY, priv crypto.PrivateKey) error {
	pubPath := prefix
	privPath := prefix
	if !strings.HasSuffix(pubPath, ".key") {
		pubPath += ".key"
	}
	if !strings.HasSuffix(privPath, ".private") {
		privPath += ".private"
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, []byte(key.String()+"\n"), 0644); err != nil {
		return err
	}
	privStr := key.PrivateKeyString(priv)
	if err := os.WriteFile(privPath, []byte(privStr), 0600); err != nil {
		return err
	}
	return nil
}

// dnskeyRRSet returns the DNSKEY RR set for a zone.
func (a *authority) dnskeyRRSet() []dns.RR {
	if a.keys == nil || !a.keys.enabled {
		return nil
	}
	var out []dns.RR
	if a.keys.zsk != nil {
		out = append(out, a.keys.zsk)
	}
	if a.keys.ksk != nil && a.keys.ksk != a.keys.zsk {
		out = append(out, a.keys.ksk)
	}
	// Add NSEC3PARAM record when NSEC3 is enabled
	if a.keys.nsec3Iterations > 0 {
		if nsec3param := a.makeNSEC3PARAM(); nsec3param != nil {
			out = append(out, nsec3param)
		}
	}
	for i := range out {
		out[i].Header().Name = ensureDot(a.zone.Name)
		out[i].Header().Ttl = a.zone.TTLAnswer
	}
	return out
}

// signAll walks over rrs and appends RRSIGs per RRset type/name (ZSK; DNSKEY uses KSK)
func (a *authority) signAll(in []dns.RR) []dns.RR {
	if a.keys == nil || !a.keys.enabled {
		return in
	}
	if len(in) == 0 {
		return in
	}
	groups := map[string][]dns.RR{}
	var out []dns.RR
	for _, rr := range in {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			out = append(out, rr)
			continue
		}
		k := strings.ToLower(rr.Header().Name) + ":" + fmt.Sprint(rr.Header().Rrtype)
		groups[k] = append(groups[k], rr)
	}
	for _, g := range groups {
		out = append(out, g...)
		key := a.keys.zsk
		priv := a.keys.zskPriv
		if len(g) > 0 && g[0].Header().Rrtype == dns.TypeDNSKEY {
			key = a.keys.ksk
			priv = a.keys.kskPriv
		}
		if key == nil || priv == nil {
			continue
		}
		sig := a.makeRRSIG(g, key)
		if err := sig.Sign(priv, g); err == nil {
			out = append(out, sig)
		} else {
			log.Printf("dnssec sign error for %s/%d: %v", g[0].Header().Name, g[0].Header().Rrtype, err)
		}
	}
	return out
}

// makeRRSIG creates an RRSIG for a given RR set.
func (a *authority) makeRRSIG(rrset []dns.RR, key *dns.DNSKEY) *dns.RRSIG {
	name := rrset[0].Header().Name
	ttl := rrset[0].Header().Ttl
	labels := uint8(strings.Count(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(name), "."), "."), ".") + 1)
	now := time.Now().UTC()
	incep := uint32(now.Add(-5 * time.Minute).Unix())
	exp := uint32(now.Add(6 * time.Hour).Unix())
	return &dns.RRSIG{Hdr: hdr(name, dns.TypeRRSIG, ttl), TypeCovered: rrset[0].Header().Rrtype, Algorithm: key.Algorithm, Labels: labels, OrigTtl: ttl, Expiration: exp, Inception: incep, KeyTag: key.KeyTag(), SignerName: ensureDot(a.zone.Name)}
}

// makeNSEC builds an NSEC record for the provided owner. The owner must exist
// in the zone index.
func (a *authority) makeNSEC(owner string) dns.RR {
	if a.zidx == nil {
		return nil
	}
	owner = strings.ToLower(ensureDot(owner))
	if !a.zidx.hasName(owner) {
		return nil
	}
	next := a.zidx.nextName(owner)
	if next == "" {
		// Wrap to apex
		next = ensureDot(a.zone.Name)
	}
	types := []uint16{}
	if t, ok := a.zidx.types[owner]; ok {
		for ty := range t {
			types = append(types, ty)
		}
	}
	return &dns.NSEC{Hdr: hdr(owner, dns.TypeNSEC, a.zone.TTLAnswer), NextDomain: next, TypeBitMap: types}
}

// makeNSEC3 builds an NSEC3 record for the provided owner name.
func (a *authority) makeNSEC3(owner string) *dns.NSEC3 {
	if a.keys == nil || a.keys.nsec3Iterations == 0 || a.zidx == nil {
		return nil
	}
	owner = strings.ToLower(ensureDot(owner))
	// Hash the owner name
	hashedOwner := dns.HashName(owner, dns.SHA1, a.keys.nsec3Iterations, a.keys.nsec3Salt)
	// Find the next hashed name in the zone
	nextHash := a.zidx.nextHashedName(hashedOwner)
	if nextHash == "" {
		// Wrap to the first hashed name
		nextHash = a.zidx.firstHashedName()
	}
	// Get the types for this name
	types := []uint16{}
	if t, ok := a.zidx.hashedTypes[hashedOwner]; ok {
		for ty := range t {
			types = append(types, ty)
		}
	}
	// Create the NSEC3 record
	return &dns.NSEC3{
		Hdr:        hdr(hashedOwner+"."+ensureDot(a.zone.Name), dns.TypeNSEC3, a.zone.TTLAnswer),
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: a.keys.nsec3Iterations,
		Salt:       a.keys.nsec3Salt,
		NextDomain: nextHash,
		TypeBitMap: types,
	}
}

// makeNSEC3PARAM builds an NSEC3PARAM record for the zone.
func (a *authority) makeNSEC3PARAM() *dns.NSEC3PARAM {
	if a.keys == nil || a.keys.nsec3Iterations == 0 {
		return nil
	}
	return &dns.NSEC3PARAM{
		Hdr:        hdr(ensureDot(a.zone.Name), dns.TypeNSEC3PARAM, a.zone.TTLAnswer),
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations:  a.keys.nsec3Iterations,
		Salt:       a.keys.nsec3Salt,
	}
}