package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func persistSecondarySnapshot(cfg *Config, z Zone, records []dns.RR, soa *dns.SOA) error {
	if cfg == nil || soa == nil {
		return nil
	}
	snap := secondarySnapshotZone(z, records, soa)
	data, err := yaml.Marshal([]Zone{snap})
	if err != nil {
		return err
	}
	path := secondarySnapshotPath(cfg, z.Name)
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	writeSerial(z.Name, soa.Serial)
	return nil
}

func secondarySnapshotPath(cfg *Config, zoneName string) string {
	if cfg == nil {
		return ""
	}
	baseDir := cfg.BaseDir
	if baseDir == "" {
		baseDir = "."
	}
	if isReverseSnapshotZone(zoneName) {
		dir := cfg.ReverseDir
		if dir == "" {
			dir = filepath.Join(baseDir, "reverse")
		}
		return filepath.Join(dir, strings.TrimSuffix(ensureDot(zoneName), ".")+".rev.yaml")
	}
	dir := cfg.ZonesDir
	if dir == "" {
		dir = filepath.Join(baseDir, "zones")
	}
	return filepath.Join(dir, strings.TrimSuffix(ensureDot(zoneName), ".")+".fwd.yaml")
}

func isReverseSnapshotZone(name string) bool {
	name = strings.ToLower(ensureDot(name))
	return strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.")
}

func secondarySnapshotZone(z Zone, records []dns.RR, soa *dns.SOA) Zone {
	snap := Zone{
		Name:      ensureDot(z.Name),
		NS:        append([]string(nil), z.NS...),
		Admin:     ensureDot(soa.Mbox),
		TTLSOA:    soa.Hdr.Ttl,
		TTLAnswer: snapshotTTLAnswer(records, z.TTLAnswer, soa.Minttl),
		Refresh:   soa.Refresh,
		Retry:     soa.Retry,
		Expire:    soa.Expire,
		Minttl:    soa.Minttl,
		Serve:     "secondary",
		Masters:   append([]string(nil), z.Masters...),
		XFRSource: z.XFRSource,
		TSIG:      cloneSnapshotTSIGZoneConfig(z.TSIG),
		DNSSEC:    cloneSnapshotDNSSECZoneConfig(z.DNSSEC),
	}

	hostMap := map[string]*Host{}
	for _, rr := range records {
		switch v := rr.(type) {
		case *dns.NS:
			if strings.EqualFold(ensureDot(v.Hdr.Name), snap.Name) {
				snap.NS = appendUniqueName(snap.NS, ensureDot(v.Ns))
			}
		case *dns.A:
			if strings.EqualFold(ensureDot(v.Hdr.Name), snap.Name) {
				snap.AFallback = appendIPAddrUnique(snap.AFallback, v.A.String())
				continue
			}
			h := ensureSnapshotHost(hostMap, &snap, v.Hdr.Name)
			addHostPoolMember(h, "snapshot-v4", "ipv4", v.A.String())
		case *dns.AAAA:
			if strings.EqualFold(ensureDot(v.Hdr.Name), snap.Name) {
				snap.AAAAFallback = appendIPAddrUnique(snap.AAAAFallback, v.AAAA.String())
				continue
			}
			h := ensureSnapshotHost(hostMap, &snap, v.Hdr.Name)
			addHostPoolMember(h, "snapshot-v6", "ipv6", v.AAAA.String())
		case *dns.TXT:
			snap.TXT = append(snap.TXT, TXTRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Text: append([]string(nil), v.Txt...), TTL: v.Hdr.Ttl})
		case *dns.MX:
			snap.MX = append(snap.MX, MXRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Preference: v.Preference, Exchange: ensureDot(v.Mx), TTL: v.Hdr.Ttl})
		case *dns.CAA:
			snap.CAA = append(snap.CAA, CAARecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Flag: v.Flag, Tag: v.Tag, Value: v.Value, TTL: v.Hdr.Ttl})
		case *dns.RP:
			snap.RP = &RPRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Mbox: ensureDot(v.Mbox), Txt: ensureDot(v.Txt), TTL: v.Hdr.Ttl}
		case *dns.SSHFP:
			snap.SSHFP = append(snap.SSHFP, SSHFPRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Algorithm: v.Algorithm, Type: v.Type, Fingerprint: v.FingerPrint, TTL: v.Hdr.Ttl})
		case *dns.SRV:
			snap.SRV = append(snap.SRV, SRVRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Priority: v.Priority, Weight: v.Weight, Port: v.Port, Target: ensureDot(v.Target), TTL: v.Hdr.Ttl})
		case *dns.NAPTR:
			snap.NAPTR = append(snap.NAPTR, NAPTRRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Order: v.Order, Preference: v.Preference, Flags: v.Flags, Services: v.Service, Regexp: v.Regexp, Replacement: ensureDot(v.Replacement), TTL: v.Hdr.Ttl})
		case *dns.PTR:
			snap.PTR = append(snap.PTR, PTRRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), PTR: ensureDot(v.Ptr), TTL: v.Hdr.Ttl})
		}
	}
	return snap
}

func ensureSnapshotHost(hostMap map[string]*Host, snap *Zone, owner string) *Host {
	name := snapshotOwnerName(snap.Name, owner)
	key := strings.ToLower(name)
	if h := hostMap[key]; h != nil {
		return h
	}
	snap.Hosts = append(snap.Hosts, Host{Name: name})
	h := &snap.Hosts[len(snap.Hosts)-1]
	hostMap[key] = h
	return h
}

func addHostPoolMember(h *Host, poolName, family, ip string) {
	for i := range h.Pools {
		if h.Pools[i].Name == poolName {
			h.Pools[i].Members = appendIPAddrUnique(h.Pools[i].Members, ip)
			return
		}
	}
	h.Pools = append(h.Pools, Pool{
		Name:    poolName,
		Family:  family,
		Class:   "public",
		Role:    "fallback",
		Members: []IPAddr{{IP: ip}},
	})
}

func appendIPAddrUnique(list []IPAddr, ip string) []IPAddr {
	for _, item := range list {
		if item.IP == ip {
			return list
		}
	}
	return append(list, IPAddr{IP: ip})
}

func appendUniqueName(list []string, name string) []string {
	for _, item := range list {
		if strings.EqualFold(ensureDot(item), ensureDot(name)) {
			return list
		}
	}
	return append(list, ensureDot(name))
}

func snapshotOwnerName(zoneName, owner string) string {
	zoneName = ensureDot(zoneName)
	owner = ensureDot(owner)
	if strings.EqualFold(zoneName, owner) {
		return "@"
	}
	if strings.HasSuffix(strings.ToLower(owner), strings.ToLower(zoneName)) {
		trimmed := strings.TrimSuffix(owner, zoneName)
		trimmed = strings.TrimSuffix(trimmed, ".")
		if trimmed != "" {
			return trimmed
		}
	}
	return owner
}

func snapshotTTLAnswer(records []dns.RR, current, minttl uint32) uint32 {
	for _, rr := range records {
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			if rr.Header().Ttl > 0 {
				return rr.Header().Ttl
			}
		}
	}
	if current > 0 {
		return current
	}
	if minttl > 0 {
		return minttl
	}
	return 60
}

func cloneSnapshotTSIGZoneConfig(t *TSIGZoneConfig) *TSIGZoneConfig {
	if t == nil {
		return nil
	}
	cp := *t
	if len(t.Keys) > 0 {
		cp.Keys = append([]TSIGKey(nil), t.Keys...)
	}
	return &cp
}

func cloneSnapshotDNSSECZoneConfig(d *DNSSECZoneConfig) *DNSSECZoneConfig {
	if d == nil {
		return nil
	}
	cp := *d
	return &cp
}
