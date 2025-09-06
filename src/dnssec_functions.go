package main

import (
	"crypto"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	config "github.com/akadatalimited/breathgslb/src/config"
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
			// Use ZSK as KSK when not specified
			k.ksk = k.zsk
			k.kskPriv = k.zskPriv
		}
	case DNSSECModeGenerated:
		fallthrough
	default:
		// Generate keys in memory or load from disk
		prefix := "K" + strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(z.Name, ".")), ".")
		zskPath := z.DNSSEC.ZSKFile
		kskPath := z.DNSSEC.KSKFile
		// Extract directory from key file paths and create directories if they don't exist
		if zskPath != "" {
			zskDir := filepath.Dir(zskPath)
			if zskDir != "" {
				_ = os.MkdirAll(zskDir, 0755)
			}
		} else {
			zskPath = filepath.Join(".", prefix+".zsk")
		}
		if kskPath != "" {
			kskDir := filepath.Dir(kskPath)
			if kskDir != "" && kskDir != filepath.Dir(zskPath) {
				_ = os.MkdirAll(kskDir, 0755)
			}
		} else {
			kskPath = filepath.Join(".", prefix+".ksk")
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
		if kskPath != "" && kskPath != zskPath {
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
			// Use ZSK as KSK when not specified or when paths are the same
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
	
	// Parse the public key as a DNSKEY record
	rr, err := dns.NewRR(string(pub))
	if err != nil {
		return nil, nil, err
	}
	k, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not a DNSKEY record")
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

// generateKeyPair generates a new DNSSEC key pair for the given algorithm.
func generateKeyPair(alg uint8) (*dns.DNSKEY, crypto.Signer) {
	k := new(dns.DNSKEY)
	k.Hdr.Rrtype = dns.TypeDNSKEY
	k.Hdr.Class = dns.ClassINET
	k.Hdr.Ttl = 3600 // Standard TTL for DNSKEY
	k.Flags = 256    // ZSK flag
	k.Protocol = 3  // DNSSEC protocol
	k.Algorithm = alg

	// Generate the key pair
	privkey, err := k.Generate(int(alg))
	if err != nil {
		log.Printf("dnssec: key generation failed: %v", err)
		return nil, nil
	}

	// Convert to crypto.Signer
	signer, ok := privkey.(crypto.Signer)
	if !ok {
		log.Printf("dnssec: private key does not implement crypto.Signer")
		return nil, nil
	}

	return k, signer
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
	typeBitmap := []uint16{}
	if t, ok := a.zidx.types[owner]; ok {
		for ty := range t {
			typeBitmap = append(typeBitmap, ty)
		}
	}
	return &dns.NSEC{Hdr: hdr(owner, dns.TypeNSEC, a.zone.TTLAnswer), NextDomain: next, TypeBitMap: typeBitmap}
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
	nextHash := a.zidx.nextName(hashedOwner)
		if nextHash == "" {
			// Wrap around to first name (use the first name in the zone)
			if len(a.zidx.names) > 0 {
				nextHash = a.zidx.names[0]
			}
		}
		// Get the types for this owner
		// Use typeBitmap instead of hashedTypes
		typeBitmap := []uint16{}
		if t := a.zidx.typeBitmap(hashedOwner); len(t) > 0 {
			for _, ty := range t {
				typeBitmap = append(typeBitmap, ty)
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
			TypeBitMap: typeBitmap,
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