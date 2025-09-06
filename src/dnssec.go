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

func (a *authority) makeRRSIG(rrset []dns.RR, key *dns.DNSKEY) *dns.RRSIG {
	name := rrset[0].Header().Name
	ttl := rrset[0].Header().Ttl
	labels := uint8(strings.Count(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(name), "."), "."), ".") + 1)
	now := time.Now().UTC()
	incep := uint32(now.Add(-5 * time.Minute).Unix())
	exp := uint32(now.Add(6 * time.Hour).Unix())
	return &dns.RRSIG{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl}, TypeCovered: rrset[0].Header().Rrtype, Algorithm: key.Algorithm, Labels: labels, OrigTtl: ttl, Expiration: exp, Inception: incep, KeyTag: key.KeyTag(), SignerName: ensureDot(a.zone.Name)}
}

// parseBindKeyPair expects pub in <prefix>.key and private in <prefix>.private
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