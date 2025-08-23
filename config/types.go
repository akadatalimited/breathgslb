package config

import "strings"
import "gopkg.in/yaml.v3"

// HealthConfig holds per-zone health probe settings.
type HealthKind string

const (
	HKHTTP  HealthKind = "http"  // existing
	HKHTTP3 HealthKind = "http3" // new: HTTP/3 over QUIC
	HKTCP   HealthKind = "tcp"   // new: TCP connect (optionally TLS)
	HKUDP   HealthKind = "udp"   // new: UDP send/expect
	HKICMP  HealthKind = "icmp"  // new: ICMP/ICMPv6 echo
	HKRawIP HealthKind = "rawip" // new: raw IP protocol probe
)

type HealthConfig struct {
	Kind        HealthKind `yaml:"kind,omitempty"`
	HostHeader  string     `yaml:"host_header,omitempty"`
	Path        string     `yaml:"path,omitempty"`
	SNI         string     `yaml:"sni,omitempty"`
	InsecureTLS bool       `yaml:"insecure_tls,omitempty"`
	Scheme      string     `yaml:"scheme,omitempty"`
	Method      string     `yaml:"method,omitempty"`
	Port        int        `yaml:"port,omitempty"`
	Expect      string     `yaml:"expect,omitempty"`

	TLSEnable  bool     `yaml:"tls_enable,omitempty"`
	ALPN       string   `yaml:"alpn,omitempty"`
	ALPNProtos []string `yaml:"-"`

	UDPPayloadB64 string `yaml:"udp_payload_b64,omitempty"`
	UDPExpectRE   string `yaml:"udp_expect_re,omitempty"`

	ICMPPayloadB64 string `yaml:"icmp_payload_b64,omitempty"`

	Protocol int `yaml:"protocol,omitempty"`
}

// ---- GeoIP config & policy ----

type GeoIPConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Database    string `yaml:"database"`
	PreferField string `yaml:"prefer_field"`
	CacheTTLSec int    `yaml:"cache_ttl_sec"`
}

type GeoTierPolicy struct {
	AllowCountries  []string `yaml:"allow_countries,omitempty"`
	AllowContinents []string `yaml:"allow_continents,omitempty"`
	AllowAll        bool     `yaml:"allow_all,omitempty"`
}

type GeoPolicy struct {
	Master   GeoTierPolicy `yaml:"master,omitempty"`
	Standby  GeoTierPolicy `yaml:"standby,omitempty"`
	Fallback GeoTierPolicy `yaml:"fallback,omitempty"`
}

type GeoAnswerSet struct {
	A           []string `yaml:"a,omitempty"`
	AAAA        []string `yaml:"aaaa,omitempty"`
	APrivate    []string `yaml:"a_private,omitempty"`
	AAAAPrivate []string `yaml:"aaaa_private,omitempty"`
	RFC         []string `yaml:"rfc,omitempty"`
	ULA         []string `yaml:"ula,omitempty"`
}

type GeoAnswers struct {
	Country   map[string]GeoAnswerSet `yaml:"country,omitempty"`
	Continent map[string]GeoAnswerSet `yaml:"continent,omitempty"`
}

// ---- DNSSEC config ----

type DNSSECZoneConfig struct {
	Enable  bool   `yaml:"enable"`
	ZSKFile string `yaml:"zsk_keyfile,omitempty"`
	KSKFile string `yaml:"ksk_keyfile,omitempty"`
}

// TSIGGlobalConfig holds global TSIG parameters.
type TSIGGlobalConfig struct {
	Path string `yaml:"path,omitempty"`
}

// TSIGKey describes a single TSIG key.
type TSIGKey struct {
	Name         string   `yaml:"name"`
	Algorithm    string   `yaml:"algorithm,omitempty"`
	Secret       string   `yaml:"secret,omitempty"`
	AllowXFRFrom []string `yaml:"allow_xfr_from,omitempty"`
}

// TSIGZoneConfig holds per-zone TSIG options.
type TSIGZoneConfig struct {
	DefaultAlgorithm string    `yaml:"default_algorithm,omitempty"`
	SeedEnv          string    `yaml:"seed_env,omitempty"`
	Epoch            int       `yaml:"epoch,omitempty"`
	Keys             []TSIGKey `yaml:"keys,omitempty"`
}

// StringSlice allows a YAML field to be either a single string or a list.
type StringSlice []string

func (ss *StringSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Value != "" {
			*ss = []string{strings.TrimSpace(value.Value)}
		}
	case yaml.SequenceNode:
		var list []string
		for _, n := range value.Content {
			list = append(list, strings.TrimSpace(n.Value))
		}
		*ss = list
	}
	return nil
}

// Config is the top-level YAML.
type Config struct {
	Listen      string   `yaml:"listen"`
	ListenAddrs []string `yaml:"listen_addrs,omitempty"`
	Interfaces  []string `yaml:"interfaces,omitempty"`
	ReverseDir  string   `yaml:"reverse_dir,omitempty"`
	Zones       []Zone   `yaml:"zones"`

	TimeoutSec  int  `yaml:"timeout_sec"`
	IntervalSec int  `yaml:"interval_sec"`
	Rise        int  `yaml:"rise"`
	Fall        int  `yaml:"fall"`
	EDNSBuf     int  `yaml:"edns_buf"`
	MaxRecords  int  `yaml:"max_records,omitempty"`
	LogQueries  bool `yaml:"log_queries"`
	MaxWorkers  int  `yaml:"max_workers"`

	JitterMs    int `yaml:"jitter_ms"`
	CooldownSec int `yaml:"cooldown_sec"`

	DNS64Prefix string `yaml:"dns64_prefix,omitempty"`

	PersistenceEnabled bool   `yaml:"persistence_enabled,omitempty"`
	PersistenceMode    string `yaml:"persistence_mode,omitempty"`

	LogFile   string `yaml:"log_file"`
	LogSyslog bool   `yaml:"log_syslog,omitempty"`

	TSIG *TSIGGlobalConfig `yaml:"tsig,omitempty"`

	GeoIP *GeoIPConfig `yaml:"geoip,omitempty"`

	API          bool        `yaml:"api,omitempty"`
	APIListen    int         `yaml:"api-listen,omitempty"`
	APIInterface StringSlice `yaml:"api-interface,omitempty"`
	APIToken     string      `yaml:"api-token,omitempty"`
	APICert      string      `yaml:"api-cert,omitempty"`
	APIKey       string      `yaml:"api-key,omitempty"`
}

// Shared record types.
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

// IPAddr represents an IP address with optional reverse generation.
type IPAddr struct {
	IP      string `yaml:"ip"`
	Reverse bool   `yaml:"reverse,omitempty"`
}

// UnmarshalYAML allows IPAddr to be specified as a scalar string or mapping.
func (a *IPAddr) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		a.IP = strings.TrimSpace(value.Value)
		return nil
	}
	var tmp struct {
		IP      string `yaml:"ip"`
		Reverse bool   `yaml:"reverse"`
	}
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	a.IP = strings.TrimSpace(tmp.IP)
	a.Reverse = tmp.Reverse
	return nil
}

// Zone defines a single authoritative child zone served here.
type Zone struct {
	Name      string   `yaml:"name"`
	NS        []string `yaml:"ns"`
	Admin     string   `yaml:"admin"`
	TTLSOA    uint32   `yaml:"ttl_soa"`
	TTLAnswer uint32   `yaml:"ttl_answer"`

	PersistenceEnabled bool   `yaml:"persistence_enabled,omitempty"`
	PersistenceMode    string `yaml:"persistence_mode,omitempty"`

	Serve                    string `yaml:"serve,omitempty"`
	PrivateAllowWhenIsolated bool   `yaml:"private_allow_when_isolated,omitempty"`

	AMaster      []IPAddr `yaml:"a_master,omitempty"`
	AAAAMaster   []IPAddr `yaml:"aaaa_master,omitempty"`
	AStandby     []IPAddr `yaml:"a_standby,omitempty"`
	AAAAStandby  []IPAddr `yaml:"aaaa_standby,omitempty"`
	AFallback    []IPAddr `yaml:"a_fallback,omitempty"`
	AAAAFallback []IPAddr `yaml:"aaaa_fallback,omitempty"`

	AMasterPrivate      []IPAddr `yaml:"a_master_private,omitempty"`
	AAAAMasterPrivate   []IPAddr `yaml:"aaaa_master_private,omitempty"`
	AStandbyPrivate     []IPAddr `yaml:"a_standby_private,omitempty"`
	AAAAStandbyPrivate  []IPAddr `yaml:"aaaa_standby_private,omitempty"`
	AFallbackPrivate    []IPAddr `yaml:"a_fallback_private,omitempty"`
	AAAAFallbackPrivate []IPAddr `yaml:"aaaa_fallback_private,omitempty"`

	RFCMaster   []string `yaml:"rfc_master,omitempty"`
	ULAMaster   []string `yaml:"ula_master,omitempty"`
	RFCStandby  []string `yaml:"rfc_standby,omitempty"`
	ULAStandby  []string `yaml:"ula_standby,omitempty"`
	RFCFallback []string `yaml:"rfc_fallback,omitempty"`
	ULAFallback []string `yaml:"ula_fallback,omitempty"`

	Alias string `yaml:"alias,omitempty"`

	TXT   []TXTRecord   `yaml:"txt,omitempty"`
	MX    []MXRecord    `yaml:"mx,omitempty"`
	CAA   []CAARecord   `yaml:"caa,omitempty"`
	RP    *RPRecord     `yaml:"rp,omitempty"`
	SSHFP []SSHFPRecord `yaml:"sshfp,omitempty"`
	SRV   []SRVRecord   `yaml:"srv,omitempty"`
	NAPTR []NAPTRRecord `yaml:"naptr,omitempty"`

	Geo        *GeoPolicy  `yaml:"geo,omitempty"`
	GeoAnswers *GeoAnswers `yaml:"geo_answers,omitempty"`

	Health *HealthConfig     `yaml:"health,omitempty"`
	DNSSEC *DNSSECZoneConfig `yaml:"dnssec,omitempty"`
	TSIG   *TSIGZoneConfig   `yaml:"tsig,omitempty"`
}
