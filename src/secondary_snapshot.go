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
	snap := cloneSnapshotZoneBase(z)
	snap.Name = ensureDot(z.Name)
	snap.Admin = ensureDot(soa.Mbox)
	snap.TTLSOA = soa.Hdr.Ttl
	snap.TTLAnswer = snapshotTTLAnswer(records, z.TTLAnswer, soa.Minttl)
	snap.Refresh = soa.Refresh
	snap.Retry = soa.Retry
	snap.Expire = soa.Expire
	snap.Minttl = soa.Minttl
	snap.Serve = "secondary"
	snap.Masters = append([]string(nil), z.Masters...)
	snap.XFRSource = z.XFRSource
	snap.TSIG = cloneSnapshotTSIGZoneConfig(z.TSIG)
	snap.DNSSEC = cloneSnapshotDNSSECZoneConfig(z.DNSSEC)

	hostMap := map[string]*Host{}
	for i := range snap.Hosts {
		hostMap[strings.ToLower(snap.Hosts[i].Name)] = &snap.Hosts[i]
	}
	for _, rr := range records {
		switch v := rr.(type) {
		case *dns.NS:
			if strings.EqualFold(ensureDot(v.Hdr.Name), snap.Name) {
				if len(snap.NS) == 0 {
					snap.NS = appendUniqueName(snap.NS, ensureDot(v.Ns))
				}
			}
		case *dns.A:
			if strings.EqualFold(ensureDot(v.Hdr.Name), snap.Name) {
				if !zoneHasConfiguredA(z) {
					snap.AFallback = appendIPAddrUnique(snap.AFallback, v.A.String())
				}
				continue
			}
			h := ensureSnapshotHost(hostMap, &snap, v.Hdr.Name)
			if !hostHasConfiguredFamily(*h, "ipv4") {
				addHostPoolMember(h, "snapshot-v4", "ipv4", v.A.String())
			}
		case *dns.AAAA:
			if strings.EqualFold(ensureDot(v.Hdr.Name), snap.Name) {
				if !zoneHasConfiguredAAAA(z) {
					snap.AAAAFallback = appendIPAddrUnique(snap.AAAAFallback, v.AAAA.String())
				}
				continue
			}
			h := ensureSnapshotHost(hostMap, &snap, v.Hdr.Name)
			if !hostHasConfiguredFamily(*h, "ipv6") {
				addHostPoolMember(h, "snapshot-v6", "ipv6", v.AAAA.String())
			}
		case *dns.TXT:
			if len(snap.TXT) == 0 {
				snap.TXT = append(snap.TXT, TXTRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Text: append([]string(nil), v.Txt...), TTL: v.Hdr.Ttl})
			}
		case *dns.MX:
			if len(snap.MX) == 0 {
				snap.MX = append(snap.MX, MXRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Preference: v.Preference, Exchange: ensureDot(v.Mx), TTL: v.Hdr.Ttl})
			}
		case *dns.CAA:
			if len(snap.CAA) == 0 {
				snap.CAA = append(snap.CAA, CAARecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Flag: v.Flag, Tag: v.Tag, Value: v.Value, TTL: v.Hdr.Ttl})
			}
		case *dns.RP:
			if snap.RP == nil {
				snap.RP = &RPRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Mbox: ensureDot(v.Mbox), Txt: ensureDot(v.Txt), TTL: v.Hdr.Ttl}
			}
		case *dns.SSHFP:
			if len(snap.SSHFP) == 0 {
				snap.SSHFP = append(snap.SSHFP, SSHFPRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Algorithm: v.Algorithm, Type: v.Type, Fingerprint: v.FingerPrint, TTL: v.Hdr.Ttl})
			}
		case *dns.SRV:
			if len(snap.SRV) == 0 {
				snap.SRV = append(snap.SRV, SRVRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Priority: v.Priority, Weight: v.Weight, Port: v.Port, Target: ensureDot(v.Target), TTL: v.Hdr.Ttl})
			}
		case *dns.NAPTR:
			if len(snap.NAPTR) == 0 {
				snap.NAPTR = append(snap.NAPTR, NAPTRRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), Order: v.Order, Preference: v.Preference, Flags: v.Flags, Services: v.Service, Regexp: v.Regexp, Replacement: ensureDot(v.Replacement), TTL: v.Hdr.Ttl})
			}
		case *dns.PTR:
			if len(snap.PTR) == 0 {
				snap.PTR = append(snap.PTR, PTRRecord{Name: snapshotOwnerName(snap.Name, v.Hdr.Name), PTR: ensureDot(v.Ptr), TTL: v.Hdr.Ttl})
			}
		}
	}
	return snap
}

func cloneSnapshotZoneBase(z Zone) Zone {
	snap := z
	snap.NS = append([]string(nil), z.NS...)
	snap.Masters = append([]string(nil), z.Masters...)
	snap.AMaster = append([]IPAddr(nil), z.AMaster...)
	snap.AAAAMaster = append([]IPAddr(nil), z.AAAAMaster...)
	snap.AStandby = append([]IPAddr(nil), z.AStandby...)
	snap.AAAAStandby = append([]IPAddr(nil), z.AAAAStandby...)
	snap.AFallback = append([]IPAddr(nil), z.AFallback...)
	snap.AAAAFallback = append([]IPAddr(nil), z.AAAAFallback...)
	snap.AMasterPrivate = append([]IPAddr(nil), z.AMasterPrivate...)
	snap.AAAAMasterPrivate = append([]IPAddr(nil), z.AAAAMasterPrivate...)
	snap.AStandbyPrivate = append([]IPAddr(nil), z.AStandbyPrivate...)
	snap.AAAAStandbyPrivate = append([]IPAddr(nil), z.AAAAStandbyPrivate...)
	snap.AFallbackPrivate = append([]IPAddr(nil), z.AFallbackPrivate...)
	snap.AAAAFallbackPrivate = append([]IPAddr(nil), z.AAAAFallbackPrivate...)
	snap.RFCMaster = append([]string(nil), z.RFCMaster...)
	snap.ULAMaster = append([]string(nil), z.ULAMaster...)
	snap.RFCStandby = append([]string(nil), z.RFCStandby...)
	snap.ULAStandby = append([]string(nil), z.ULAStandby...)
	snap.RFCFallback = append([]string(nil), z.RFCFallback...)
	snap.ULAFallback = append([]string(nil), z.ULAFallback...)
	if z.AliasHost != nil {
		snap.AliasHost = make(map[string]string, len(z.AliasHost))
		for k, v := range z.AliasHost {
			snap.AliasHost[k] = v
		}
	}
	if len(z.Hosts) > 0 {
		snap.Hosts = make([]Host, len(z.Hosts))
		for i := range z.Hosts {
			snap.Hosts[i] = cloneSnapshotHost(z.Hosts[i])
		}
	}
	if len(z.Pools) > 0 {
		snap.Pools = make([]Pool, len(z.Pools))
		for i := range z.Pools {
			snap.Pools[i] = cloneSnapshotPool(z.Pools[i])
		}
	}
	snap.TXT = append([]TXTRecord(nil), z.TXT...)
	snap.MX = append([]MXRecord(nil), z.MX...)
	snap.CAA = append([]CAARecord(nil), z.CAA...)
	if z.RP != nil {
		cp := *z.RP
		snap.RP = &cp
	}
	snap.SSHFP = append([]SSHFPRecord(nil), z.SSHFP...)
	snap.SRV = append([]SRVRecord(nil), z.SRV...)
	snap.NAPTR = append([]NAPTRRecord(nil), z.NAPTR...)
	snap.PTR = append([]PTRRecord(nil), z.PTR...)
	if z.Geo != nil {
		cp := *z.Geo
		if len(z.Geo.Named) > 0 {
			cp.Named = append([]NamedGeoPolicy(nil), z.Geo.Named...)
		}
		snap.Geo = &cp
	}
	if z.GeoAnswers != nil {
		cp := *z.GeoAnswers
		snap.GeoAnswers = &cp
	}
	if z.Lightup != nil {
		cp := *z.Lightup
		cp.Exclude = append([]string(nil), z.Lightup.Exclude...)
		cp.Families = append([]LightupFamily(nil), z.Lightup.Families...)
		cp.NSAAAA = append([]string(nil), z.Lightup.NSAAAA...)
		snap.Lightup = &cp
	}
	if z.Health != nil {
		cp := *z.Health
		cp.ALPNProtos = append([]string(nil), z.Health.ALPNProtos...)
		snap.Health = &cp
	}
	return snap
}

func cloneSnapshotHost(h Host) Host {
	out := h
	if len(h.Pools) > 0 {
		out.Pools = make([]Pool, len(h.Pools))
		for i := range h.Pools {
			out.Pools[i] = cloneSnapshotPool(h.Pools[i])
		}
	}
	if h.Geo != nil {
		cp := *h.Geo
		if len(h.Geo.Named) > 0 {
			cp.Named = append([]NamedGeoPolicy(nil), h.Geo.Named...)
		}
		out.Geo = &cp
	}
	if h.Health != nil {
		cp := *h.Health
		cp.ALPNProtos = append([]string(nil), h.Health.ALPNProtos...)
		out.Health = &cp
	}
	return out
}

func cloneSnapshotPool(p Pool) Pool {
	out := p
	out.Members = append([]IPAddr(nil), p.Members...)
	out.ClientNets = append([]string(nil), p.ClientNets...)
	return out
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

func zoneHasConfiguredA(z Zone) bool {
	return len(z.AMaster) > 0 || len(z.AStandby) > 0 || len(z.AFallback) > 0 ||
		len(z.AMasterPrivate) > 0 || len(z.AStandbyPrivate) > 0 || len(z.AFallbackPrivate) > 0 ||
		len(z.Pools) > 0 || z.Alias != ""
}

func zoneHasConfiguredAAAA(z Zone) bool {
	return len(z.AAAAMaster) > 0 || len(z.AAAAStandby) > 0 || len(z.AAAAFallback) > 0 ||
		len(z.AAAAMasterPrivate) > 0 || len(z.AAAAStandbyPrivate) > 0 || len(z.AAAAFallbackPrivate) > 0 ||
		len(z.Pools) > 0 || z.Alias != ""
}

func hostHasConfiguredFamily(h Host, family string) bool {
	family = strings.ToLower(strings.TrimSpace(family))
	if h.Alias != "" {
		return true
	}
	for _, p := range h.Pools {
		if strings.ToLower(strings.TrimSpace(p.Family)) == family {
			return true
		}
	}
	return false
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
