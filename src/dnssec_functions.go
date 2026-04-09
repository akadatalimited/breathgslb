package main

import (
	"crypto"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	config "github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
)

// DNSSEC functions

func loadDNSSEC(z config.Zone) *DnssecKeys {
	if z.DNSSEC == nil || z.DNSSEC.Mode == "" || z.DNSSEC.Mode == DNSSECModeOff {
		return &DnssecKeys{enabled: false}
	}

	baseZ := strings.TrimSuffix(ensureDot(z.Name), ".")
	keys := &DnssecKeys{enabled: false}

	switch z.DNSSEC.Mode {
	case DNSSECModeManual:
		zskPath := z.DNSSEC.ZSKFile
		kskPath := z.DNSSEC.KSKFile
		if zskPath == "" {
			return keys
		}
		if kskPath == "" {
			kskPath = zskPath
		}
		zsk, zskPriv, err := parseBindKeyPair(baseZ, zskPath)
		if err != nil {
			log.Printf("dnssec zsk load failed: %v", err)
			return keys
		}
		keys.enabled = true
		keys.zsk = zsk
		keys.zskPriv = zskPriv
		if zskPath == kskPath {
			keys.ksk = zsk
			keys.kskPriv = zskPriv
		} else {
			ksk, kskPriv, err := parseBindKeyPair(baseZ, kskPath)
			if err != nil {
				log.Printf("dnssec ksk load failed: %v", err)
				return &DnssecKeys{enabled: false}
			}
			keys.ksk = ksk
			keys.kskPriv = kskPriv
		}

	case DNSSECModeGenerated:
		zskPath := z.DNSSEC.ZSKFile
		kskPath := z.DNSSEC.KSKFile
		if zskPath == "" {
			zskPath = filepath.Join(".", baseZ)
		}
		if kskPath == "" {
			kskPath = zskPath
		}
		if zskPath == kskPath {
			zskPath += ".zsk"
			kskPath += ".ksk"
		}

		zsk, zskPriv, err := parseBindKeyPair(baseZ, zskPath)
		if err != nil {
			zsk = &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: ensureDot(z.Name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     256,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
			}
			priv, genErr := zsk.Generate(256)
			if genErr != nil {
				log.Printf("dnssec zsk generate failed: %v", genErr)
				return keys
			}
			zskPriv, _ = priv.(crypto.Signer)
			if zskPriv == nil {
				log.Printf("dnssec zsk priv not signer")
				return keys
			}
			if writeErr := writeBindKeyPair(zskPath, zsk, priv); writeErr != nil {
				log.Printf("dnssec zsk persist failed: %v", writeErr)
			}
		}

		ksk, kskPriv, err := parseBindKeyPair(baseZ, kskPath)
		if err != nil {
			ksk = &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: ensureDot(z.Name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
			}
			priv, genErr := ksk.Generate(256)
			if genErr != nil {
				log.Printf("dnssec ksk generate failed: %v", genErr)
				return keys
			}
			kskPriv, _ = priv.(crypto.Signer)
			if kskPriv == nil {
				log.Printf("dnssec ksk priv not signer")
				return keys
			}
			if writeErr := writeBindKeyPair(kskPath, ksk, priv); writeErr != nil {
				log.Printf("dnssec ksk persist failed: %v", writeErr)
			}
		}

		keys.enabled = true
		keys.zsk = zsk
		keys.zskPriv = zskPriv
		keys.ksk = ksk
		keys.kskPriv = kskPriv

	default:
		log.Printf("dnssec mode %q not supported", z.DNSSEC.Mode)
		return keys
	}

	if keys.enabled && z.DNSSEC.NSEC3Iterations > 0 {
		keys.nsec3Iterations = z.DNSSEC.NSEC3Iterations
		keys.nsec3Salt = z.DNSSEC.NSEC3Salt
		keys.nsec3OptOut = z.DNSSEC.NSEC3OptOut
	}

	return keys
}

// Expect pub in <prefix>.key and private in <prefix>.private.
func parseBindKeyPair(zone string, prefix string) (*dns.DNSKEY, crypto.Signer, error) {
	pubPath := prefix
	privPath := prefix
	if !strings.HasSuffix(pubPath, ".key") {
		pubPath += ".key"
	}
	if !strings.HasSuffix(privPath, ".private") {
		privPath += ".private"
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, err
	}
	rr, err := dns.NewRR(string(pubData))
	if err != nil {
		return nil, nil, err
	}
	dk, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, nil, fmt.Errorf("not a DNSKEY in %s", pubPath)
	}
	f, err := os.Open(privPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	privAny, err := dk.ReadPrivateKey(f, privPath)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := privAny.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key %s does not implement crypto.Signer", privPath)
	}
	return dk, signer, nil
}

func writeBindKeyPair(prefix string, key *dns.DNSKEY, priv crypto.PrivateKey) error {
	pubPath := prefix
	privPath := prefix
	if !strings.HasSuffix(pubPath, ".key") {
		pubPath += ".key"
	}
	if !strings.HasSuffix(privPath, ".private") {
		privPath += ".private"
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, []byte(key.String()+"\n"), 0o644); err != nil {
		return err
	}
	privStr := key.PrivateKeyString(priv)
	if err := os.WriteFile(privPath, []byte(privStr), 0o600); err != nil {
		return err
	}
	return nil
}

func (a *authority) dnskeyRRSet() []dns.RR {
	if a.keys == nil || !a.keys.enabled {
		return nil
	}
	var out []dns.RR
	if a.keys.zsk != nil {
		rr := *a.keys.zsk
		out = append(out, &rr)
	}
	if a.keys.ksk != nil && a.keys.ksk != a.keys.zsk {
		rr := *a.keys.ksk
		out = append(out, &rr)
	}
	for i := range out {
		out[i].Header().Name = ensureDot(a.zone.Name)
		out[i].Header().Ttl = a.zone.TTLAnswer
	}
	return out
}

// signAll walks over rrs and appends RRSIGs per RRset type/name (ZSK; DNSKEY uses KSK).
func (a *authority) signAll(in []dns.RR) []dns.RR {
	if a.keys == nil || !a.keys.enabled {
		return in
	}
	if len(in) == 0 {
		return in
	}
	groups := map[string][]dns.RR{}
	order := []string{}
	var out []dns.RR
	for _, rr := range in {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			out = append(out, rr)
			continue
		}
		k := strings.ToLower(rr.Header().Name) + ":" + fmt.Sprint(rr.Header().Rrtype)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], rr)
	}
	for _, k := range order {
		g := groups[k]
		out = append(out, g...)
		out = append(out, a.rrsetSignatures(g)...)
	}
	return out
}

func (a *authority) rrsetSignatures(rrset []dns.RR) []dns.RR {
	if a.keys == nil || !a.keys.enabled || len(rrset) == 0 {
		return nil
	}
	key := a.keys.zsk
	priv := a.keys.zskPriv
	if rrset[0].Header().Rrtype == dns.TypeDNSKEY {
		key = a.keys.ksk
		priv = a.keys.kskPriv
	}
	if key == nil || priv == nil {
		return nil
	}

	sorted := append([]dns.RR(nil), rrset...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })
	cacheKey := a.sigCacheKey(sorted)

	now := uint32(time.Now().UTC().Unix())
	a.sigMu.Lock()
	if cached, ok := a.sigCache[cacheKey]; ok && cached.exp > now+60 {
		out := append([]dns.RR(nil), cached.sigs...)
		a.sigMu.Unlock()
		return out
	}
	a.sigMu.Unlock()

	sig := a.makeRRSIG(sorted, key)
	if err := sig.Sign(priv, sorted); err != nil {
		log.Printf("dnssec sign error for %s/%d: %v", sorted[0].Header().Name, sorted[0].Header().Rrtype, err)
		return nil
	}
	out := []dns.RR{sig}
	a.sigMu.Lock()
	a.sigCache[cacheKey] = sigCacheEntry{sigs: out, exp: sig.Expiration}
	a.sigMu.Unlock()
	return append([]dns.RR(nil), out...)
}

func (a *authority) sigCacheKey(rrset []dns.RR) string {
	var b strings.Builder
	for _, rr := range rrset {
		b.WriteString(rr.Header().Name)
		b.WriteByte('|')
		b.WriteString(fmt.Sprint(rr.Header().Rrtype))
		b.WriteByte('|')
		b.WriteString(rr.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func (a *authority) makeRRSIG(rrset []dns.RR, key *dns.DNSKEY) *dns.RRSIG {
	name := rrset[0].Header().Name
	ttl := rrset[0].Header().Ttl
	labels := uint8(strings.Count(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(name), "."), "."), ".") + 1)
	now := time.Now().UTC()
	incep := uint32(now.Add(-5 * time.Minute).Unix())
	exp := uint32(now.Add(6 * time.Hour).Unix())
	return &dns.RRSIG{
		Hdr:         hdr(name, dns.TypeRRSIG, ttl),
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      labels,
		OrigTtl:     ttl,
		Expiration:  exp,
		Inception:   incep,
		KeyTag:      key.KeyTag(),
		SignerName:  ensureDot(a.zone.Name),
	}
}

// makeNSEC builds an NSEC record for the provided owner. The owner must exist in the zone index.
func (a *authority) makeNSEC(owner string) dns.RR {
	return a.makeNSECForQuery(owner, nil, nil)
}

func (a *authority) makeNSECForQuery(owner string, src net.IP, r *dns.Msg) dns.RR {
	owner = strings.ToLower(ensureDot(owner))
	if a.zidx == nil {
		return nil
	}
	next := a.zidx.nextName(owner)
	typesHere := a.effectiveTypeBitmap(owner, src, r)
	if len(typesHere) == 0 {
		return nil
	}
	zname := strings.ToLower(ensureDot(a.zone.Name))
	bm := make([]uint16, 0, len(typesHere)+2)
	if owner == zname {
		bm = append(bm, typesHere...)
	} else {
		for _, t := range typesHere {
			if t == dns.TypeSOA || t == dns.TypeDNSKEY {
				continue
			}
			bm = append(bm, t)
		}
	}

	hasNSEC, hasRRSIG := false, false
	for _, t := range bm {
		if t == dns.TypeNSEC {
			hasNSEC = true
		}
		if t == dns.TypeRRSIG {
			hasRRSIG = true
		}
	}
	if !hasNSEC {
		bm = append(bm, dns.TypeNSEC)
	}
	if !hasRRSIG {
		bm = append(bm, dns.TypeRRSIG)
	}
	sort.Slice(bm, func(i, j int) bool { return bm[i] < bm[j] })

	return &dns.NSEC{Hdr: hdr(owner, dns.TypeNSEC, a.zone.TTLAnswer), NextDomain: ensureDot(next), TypeBitMap: bm}
}

func (a *authority) makeNSEC3(owner string) *dns.NSEC3 {
	return a.makeNSEC3ForQuery(owner, nil, nil)
}

func (a *authority) makeNSEC3ForQuery(owner string, src net.IP, r *dns.Msg) *dns.NSEC3 {
	if a.keys == nil || a.keys.nsec3Iterations == 0 || a.zidx == nil || len(a.zidx.nsec3Names) == 0 {
		return nil
	}

	queryHash := a.zidx.nsec3Hash(owner, a.keys.nsec3Iterations, a.keys.nsec3Salt)
	if !a.zidx.hasName(owner) && len(a.effectiveTypeBitmap(owner, src, r)) > 0 {
		nextHash := a.zidx.nsec3NextHash(queryHash)
		flags := uint8(0)
		if a.keys.nsec3OptOut {
			flags = 1
		}
		return &dns.NSEC3{
			Hdr:        hdr(queryHash+"."+ensureDot(a.zone.Name), dns.TypeNSEC3, a.zone.TTLAnswer),
			Hash:       dns.SHA1,
			Flags:      flags,
			Iterations: a.keys.nsec3Iterations,
			SaltLength: uint8(len(a.keys.nsec3Salt) / 2),
			Salt:       a.keys.nsec3Salt,
			HashLength: 20,
			NextDomain: nextHash,
			TypeBitMap: a.nsec3TypeBitmapForOwner(owner, src, r),
		}
	}
	coverHash := a.zidx.nsec3CoveringHash(queryHash)
	coverOwner := a.zidx.nsec3OwnerName(coverHash)
	if coverHash == "" || coverOwner == "" {
		return nil
	}

	nextHash := a.zidx.nsec3NextHash(coverHash)
	flags := uint8(0)
	if a.keys.nsec3OptOut {
		flags = 1
	}

	return &dns.NSEC3{
		Hdr:        hdr(coverHash+"."+ensureDot(a.zone.Name), dns.TypeNSEC3, a.zone.TTLAnswer),
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: a.keys.nsec3Iterations,
		SaltLength: uint8(len(a.keys.nsec3Salt) / 2),
		Salt:       a.keys.nsec3Salt,
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: a.nsec3TypeBitmapForOwner(coverOwner, src, r),
	}
}

func (a *authority) makeNSEC3PARAM() *dns.NSEC3PARAM {
	if a.keys == nil || a.keys.nsec3Iterations == 0 {
		return nil
	}
	flags := uint8(0)
	if a.keys.nsec3OptOut {
		flags = 1
	}
	return &dns.NSEC3PARAM{
		Hdr:        hdr(ensureDot(a.zone.Name), dns.TypeNSEC3PARAM, a.zone.TTLAnswer),
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: a.keys.nsec3Iterations,
		SaltLength: uint8(len(a.keys.nsec3Salt) / 2),
		Salt:       a.keys.nsec3Salt,
	}
}

func (a *authority) nsec3TypeBitmapForOwner(owner string, src net.IP, r *dns.Msg) []uint16 {
	typesHere := a.effectiveTypeBitmap(owner, src, r)
	zname := strings.ToLower(ensureDot(a.zone.Name))
	seen := make(map[uint16]bool, len(typesHere)+2)
	var bm []uint16
	for _, t := range typesHere {
		switch t {
		case dns.TypeNSEC, dns.TypeNSEC3:
			continue
		case dns.TypeSOA, dns.TypeDNSKEY:
			if owner != zname {
				continue
			}
		}
		if !seen[t] {
			seen[t] = true
			bm = append(bm, t)
		}
	}
	for _, t := range []uint16{dns.TypeNSEC3, dns.TypeRRSIG} {
		if !seen[t] {
			seen[t] = true
			bm = append(bm, t)
		}
	}
	sort.Slice(bm, func(i, j int) bool { return bm[i] < bm[j] })
	return bm
}

func (a *authority) effectiveTypeBitmap(owner string, src net.IP, r *dns.Msg) []uint16 {
	owner = strings.ToLower(ensureDot(owner))
	seen := map[uint16]bool{}
	var out []uint16
	add := func(typ uint16) {
		if !seen[typ] {
			seen[typ] = true
			out = append(out, typ)
		}
	}

	if a.zidx != nil {
		for _, typ := range a.zidx.typeBitmap(owner) {
			add(typ)
		}
	}
	for _, typ := range a.runtimeTypeBitmap(owner) {
		add(typ)
	}
	if src == nil || r == nil {
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}

	if len(a.addrA(owner, src, r)) > 0 {
		add(dns.TypeA)
	} else if seen[dns.TypeA] {
		out = removeRRType(out, dns.TypeA)
		delete(seen, dns.TypeA)
	}
	if len(a.addrAAAA(owner, src, r)) > 0 {
		add(dns.TypeAAAA)
	} else if seen[dns.TypeAAAA] {
		out = removeRRType(out, dns.TypeAAAA)
		delete(seen, dns.TypeAAAA)
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (a *authority) nsec3DenialProofs(name string) []dns.RR {
	if a.keys == nil || a.keys.nsec3Iterations == 0 || a.zidx == nil {
		return nil
	}

	proofs := map[string]*dns.NSEC3{}
	var order []string
	add := func(owner string) {
		if rr := a.makeNSEC3(owner); rr != nil {
			key := strings.ToLower(rr.Hdr.Name) + "|" + strings.ToLower(rr.NextDomain)
			if _, ok := proofs[key]; ok {
				return
			}
			proofs[key] = rr
			order = append(order, key)
		}
	}

	add(name)
	if closest := a.zidx.closestEncloser(name); closest != "" {
		add("*." + closest)
		needClosest := len(order) == 1 && len(a.zidx.names) > 2
		if !needClosest && len(order) == 1 && strings.EqualFold(closest, a.zone.Name) {
			apex := strings.ToLower(ensureDot(a.zone.Name))
			for _, owner := range a.zidx.names {
				if owner != apex && strings.HasPrefix(owner, "_") {
					needClosest = true
					break
				}
			}
		}
		if needClosest {
			add(closest)
		}
	}

	out := make([]dns.RR, 0, len(order))
	for _, key := range order {
		out = append(out, proofs[key])
	}
	return out
}
