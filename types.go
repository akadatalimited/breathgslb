package main

import (
	"context"
	"crypto"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// ---- Health ----

type HealthConfig struct {
	HostHeader  string `yaml:"host_header"`
	Path        string `yaml:"path"`
	SNI         string `yaml:"sni"`
	InsecureTLS bool   `yaml:"insecure_tls"`
}

// ---- GeoIP config & policy ----

type GeoIPConfig struct {
	Enabled     bool   `yaml:"enabled"`           // enable GeoIP reader
	Database    string `yaml:"database"`          // path to GeoLite2-Country.mmdb
	PreferField string `yaml:"prefer_field"`      // "registered" | "country" (default registered)
	CacheTTLSec int    `yaml:"cache_ttl_sec"`     // default 600
}

type GeoTierPolicy struct {
	AllowCountries  []string `yaml:"allow_countries,omitempty"`   // ISO 2-letter codes, e.g. GB, US
	AllowContinents []string `yaml:"allow_continents,omitempty"`  // 2-letter codes, e.g. EU, NA
	AllowAll        bool     `yaml:"allow_all,omitempty"`         // if true, tier is eligible for any geo
}

type GeoPolicy struct {
	Master   GeoTierPolicy `yaml:"master,omitempty"`
	Standby  GeoTierPolicy `yaml:"standby,omitempty"`
	Fallback GeoTierPolicy `yaml:"fallback,omitempty"`
}

type GeoAnswerSet struct {
	A            []string `yaml:"a,omitempty"`
	AAAA         []string `yaml:"aaaa,omitempty"`
	APrivate     []string `yaml:"a_private,omitempty"`
	AAAAPrivate  []string `yaml:"aaaa_private,omitempty"`
	RFC          []string `yaml:"rfc,omitempty"`
	ULA          []string `yaml:"ula,omitempty"`
}

type GeoAnswers struct {
	Country   map[string]GeoAnswerSet `yaml:"country,omitempty"`
	Continent map[string]GeoAnswerSet `yaml:"continent,omitempty"`
}

// ---- DNSSEC config ----

type DNSSECZoneConfig struct {
	Enable  bool   `yaml:"enable"`
	ZSKFile string `yaml:"zsk_keyfile,omitempty"` // BIND-style prefix without extension
	KSKFile string `yaml:"ksk_keyfile,omitempty"` // if empty, ZSKFile is used for both
}

// ---- Top-level config ----

type Config struct {
	Listen      string   `yaml:"listen"`
	ListenAddrs []string `yaml:"listen_addrs,omitempty"`
	Interfaces  []string `yaml:"interfaces,omitempty"`
	Zones       []Zone   `yaml:"zones"`

	TimeoutSec  int  `yaml:"timeout_sec"`
	IntervalSec int  `yaml:"interval_sec"`
	Rise        int  `yaml:"rise"`
	Fall        int  `yaml:"fall"`
	EDNSBuf     int  `yaml:"edns_buf"`
	LogQueries  bool `yaml:"log_queries"`

	// Softening knobs
	JitterMs    int `yaml:"jitter_ms"`
	CooldownSec int `yaml:"cooldown_sec"`

	// Optional file logging
	LogFile string `yaml:"log_file"`

	// Optional GeoIP steering
	GeoIP *GeoIPConfig `yaml:"geoip,omitempty"`
}

// ---- Shared/static record models ----

type TXTRecord struct {
	Name string   `yaml:"name,omitempty"`
	Text []string `yaml:"text"`
	TTL  uint32   `yaml:"ttl,omitempty"`
}

type MXRecord struct {
	Name       string `yaml:"name,omitempty"`
	Preference uint16 `yaml:"preference"`
	Exchange   string `yaml:"exchange"`
	TTL        uint32 `yaml:"ttl,omitempty"`
}

type CAARecord struct {
	Name  string `yaml:"name,omitempty"`
	Flag  uint8  `yaml:"flag"`
	Tag   string `yaml:"tag"`
	Value string `yaml:"value"`
	TTL   uint32 `yaml:"ttl,omitempty"`
}

type RPRecord struct {
	Name string `yaml:"name,omitempty"`
	Mbox string `yaml:"mbox"`
	Txt  string `yaml:"txt"`
	TTL  uint32 `yaml:"ttl,omitempty"`
}

type SSHFPRecord struct {
	Name        string `yaml:"name,omitempty"`
	Algorithm   uint8  `yaml:"algorithm"`
	Type        uint8  `yaml:"type"`
	Fingerprint string `yaml:"fingerprint"`
	TTL         uint32 `yaml:"ttl,omitempty"`
}

type SRVRecord struct {
	Name     string `yaml:"name"`
	Priority uint16 `yaml:"priority"`
	Weight   uint16 `yaml:"weight"`
	Port     uint16 `yaml:"port"`
	Target   string `yaml:"target"`
	TTL      uint32 `yaml:"ttl,omitempty"`
}

type NAPTRRecord struct {
	Name        string `yaml:"name"`
	Order       uint16 `yaml:"order"`
	Preference  uint16 `yaml:"preference"`
	Flags       string `yaml:"flags"`
	Services    string `yaml:"services"`
	Regexp      string `yaml:"regexp"`
	Replacement string `yaml:"replacement"`
	TTL         uint32 `yaml:"ttl,omitempty"`
}

// ---- Zone model ----

type Zone struct {
	Name      string   `yaml:"name"`       // FQDN with trailing dot
	NS        []string `yaml:"ns"`         // FQDNs with trailing dots
	Admin     string   `yaml:"admin"`      // hostmaster email as hostmaster.example.com.
	TTLSOA    uint32   `yaml:"ttl_soa"`
	TTLAnswer uint32   `yaml:"ttl_answer"`

	// View control
	Serve                    string `yaml:"serve,omitempty"` // "global" | "local" (default: global)
	PrivateAllowWhenIsolated bool   `yaml:"private_allow_when_isolated,omitempty"`

	// Tiered public answers
	AMaster      []string `yaml:"a_master,omitempty"`
	AAAAMaster   []string `yaml:"aaaa_master,omitempty"`
	AStandby     []string `yaml:"a_standby,omitempty"`
	AAAAStandby  []string `yaml:"aaaa_standby,omitempty"`
	AFallback    []string `yaml:"a_fallback,omitempty"`
	AAAAFallback []string `yaml:"aaaa_fallback,omitempty"`

	// Optional per-tier private answers (served only to local source ranges)
	AMasterPrivate      []string `yaml:"a_master_private,omitempty"`
	AAAAMasterPrivate   []string `yaml:"aaaa_master_private,omitempty"`
	AStandbyPrivate     []string `yaml:"a_standby_private,omitempty"`
	AAAAStandbyPrivate  []string `yaml:"aaaa_standby_private,omitempty"`
	AFallbackPrivate    []string `yaml:"a_fallback_private,omitempty"`
	AAAAFallbackPrivate []string `yaml:"aaaa_fallback_private,omitempty"`

	// Per-tier local source ranges (RFC1918 and ULA)
	RFCMaster   []string `yaml:"rfc_master,omitempty"`
	ULAMaster   []string `yaml:"ula_master,omitempty"`
	RFCStandby  []string `yaml:"rfc_standby,omitempty"`
	ULAStandby  []string `yaml:"ula_standby,omitempty"`
	RFCFallback []string `yaml:"rfc_fallback,omitempty"`
	ULAFallback []string `yaml:"ula_fallback,omitempty"`

	// Optional ALIAS-like target when no explicit A/AAAA (unchanged)
	Alias string `yaml:"alias,omitempty"`

	// Shared/static records
	TXT   []TXTRecord   `yaml:"txt,omitempty"`
	MX    []MXRecord    `yaml:"mx,omitempty"`
	CAA   []CAARecord   `yaml:"caa,omitempty"`
	RP    *RPRecord     `yaml:"rp,omitempty"`
	SSHFP []SSHFPRecord `yaml:"sshfp,omitempty"`
	SRV   []SRVRecord   `yaml:"srv,omitempty"`
	NAPTR []NAPTRRecord `yaml:"naptr,omitempty"`

	// Geo steering policy (optional)
	Geo        *GeoPolicy  `yaml:"geo,omitempty"`
	// Optional direct geo overrides (answers per country/continent)
	GeoAnswers *GeoAnswers `yaml:"geo_answers,omitempty"`

	Health HealthConfig      `yaml:"health"`
	DNSSEC *DNSSECZoneConfig `yaml:"dnssec,omitempty"`
}

// ---- runtime state ----

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

// ---- DNSSEC runtime ----

type dnssecKeys struct {
	enabled bool
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer
	ksk     *dns.DNSKEY // may equal zsk
	kskPriv crypto.Signer
}

// ---- zone index ----

type zoneIndex struct {
	names []string
	types map[string]map[uint16]bool
}

// ---- parsed local CIDRs per tier ----

type parsedCIDRs struct {
	rfc []*net.IPNet
	ula []*net.IPNet
}

type tierCIDR struct {
	master   parsedCIDRs
	standby  parsedCIDRs
	fallback parsedCIDRs
}

// ---- Geo resolver & cache ----

type geoResolver struct {
	db               *maxminddb.Reader
	preferRegistered bool
	mu    sync.RWMutex
	cache map[string]geoCacheEntry
	ttl   time.Duration
}

type geoCacheEntry struct { country, continent string; exp time.Time }

type mmdbCountry struct {
	Country struct { ISOCode string `maxminddb:"iso_code"` } `maxminddb:"country"`
	RegisteredCountry struct { ISOCode string `maxminddb:"iso_code"` } `maxminddb:"registered_country"`
	Continent struct { Code string `maxminddb:"code"` } `maxminddb:"continent"`
}

// ---- authority instance ----

type authority struct {
	cfg   *Config
	zone  Zone
	state *state

	ctx    context.Context
	cancel context.CancelFunc

	keys *dnssecKeys
	zidx *zoneIndex

	cidrs tierCIDR
	geo   *geoResolver

	// parsed CIDRs for geo_answers
	geoCIDR struct {
		country   map[string]parsedCIDRs
		continent map[string]parsedCIDRs
	}
}

// ---- router wrapper (hot-swappable) ----

type router struct {
	inner atomic.Value // dns.Handler
	edns  atomic.Uint32
}
