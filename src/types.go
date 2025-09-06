package main

import (
	"context"
	"crypto"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// ---- state: per-tier, per-family ----

type famState struct {
	up         bool
	rise, fall int
	lastChange time.Time
}

type tierState struct {
	v4 famState
	v6 famState
}

type state struct {
	mu       sync.RWMutex
	cooldown time.Duration
	master   tierState
	standby  tierState
}

// ---- DNSSEC runtime structures ----

// dnssecKeys holds DNSSEC key material for a zone.
type dnssecKeys struct {
	enabled bool
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer
	ksk     *dns.DNSKEY // may equal zsk
	kskPriv crypto.Signer

	// NSEC3 parameters
	nsec3Iterations uint16
	nsec3Salt       string
	nsec3OptOut     bool
}

// DnssecKeys is an exported alias for dnssecKeys for backward compatibility.
type DnssecKeys = dnssecKeys

// zoneIndex tracks owner names and type bitmaps for NSEC.
type zoneIndex struct {
	names []string
	types map[string]map[uint16]bool
}

// parsed local CIDRs per tier

type parsedCIDRs struct {
	rfc []*net.IPNet
	ula []*net.IPNet
}

type tierCIDR struct {
	master   parsedCIDRs
	standby  parsedCIDRs
	fallback parsedCIDRs
}

// Geo resolver & cache

type geoResolver struct {
	db               *maxminddb.Reader
	preferRegistered bool
	mu               sync.RWMutex
	cache            map[string]geoCacheEntry
	ttl              time.Duration
}

type geoCacheEntry struct {
	country, continent string
	exp                time.Time
}

type mmdbCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	Continent struct {
		Code string `maxminddb:"continent"`
	} `maxminddb:"continent"`
}

// authority binds config + zone + state + dnssec + index and runs health.

type authority struct {
	cfg   *Config
	zone  config.Zone
	state *state

	serial uint32

	ixfr *ixfrDelta

	ctx    context.Context
	cancel context.CancelFunc

	keys *DnssecKeys
	zidx *zoneIndex

	cidrs tierCIDR
	geo   *geoResolver

	persistA    sync.Map
	persistAAAA sync.Map
	rrA         atomic.Uint64
	rrAAAA      atomic.Uint64

	// secondary zone data
	mu      sync.RWMutex
	records map[string][]dns.RR
	axfrRRs []dns.RR
	soaRR   *dns.SOA

	// parsed CIDRs for geo_answers
	geoCIDR struct {
		country   map[string]parsedCIDRs
		continent map[string]parsedCIDRs
	}
}

type persistEntry struct {
	ip  string
	exp time.Time
}

type ixfrDelta struct {
	old *dns.SOA
	del []dns.RR
	new *dns.SOA
	add []dns.RR
}

// router is a dynamic handler wrapper we can hot-swap on HUP.

type router struct {
	inner atomic.Value // dns.Handler
	edns  atomic.Uint32
}

// ---- globals for reload ----

type supState struct {
	Running  bool      `json:"running"`
	Restarts int       `json:"restarts"`
	LastExit time.Time `json:"last_exit,omitempty"`
}

type supervisor struct {
	mu     sync.RWMutex
	states map[string]supState
}

type udpResponseWriter struct {
	conn    *net.UDPConn
	session *dns.SessionUDP
}
