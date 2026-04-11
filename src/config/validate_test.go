package config

import (
	"strings"
	"testing"
)

func TestValidateIPList(t *testing.T) {
	tests := []struct {
		name    string
		list    []string
		ipv6    bool
		wantErr bool
	}{
		{"ValidIPv4Private", []string{"192.168.1.1"}, false, false},
		{"InvalidIPv4", []string{"192.168.1.256"}, false, true},
		{"ValidIPv6ULA", []string{"fd00::1"}, true, false},
		{"InvalidIPv6", []string{"fd00:::1"}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIPList(tt.list, tt.ipv6, "field"); (err != nil) != tt.wantErr {
				t.Fatalf("ValidateIPList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPAddrList(t *testing.T) {
	tests := []struct {
		name    string
		list    []IPAddr
		ipv6    bool
		wantErr bool
	}{
		{"ValidIPv4Private", []IPAddr{{IP: "192.168.1.1"}}, false, false},
		{"InvalidIPv4", []IPAddr{{IP: "fd00::1"}}, false, true},
		{"ValidIPv6ULA", []IPAddr{{IP: "fd00::1"}}, true, false},
		{"InvalidIPv6", []IPAddr{{IP: "192.168.1.1"}}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIPAddrList(tt.list, tt.ipv6, "field"); (err != nil) != tt.wantErr {
				t.Fatalf("ValidateIPAddrList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateGeoAnswerSet(t *testing.T) {
	valid := GeoAnswerSet{
		A:           []string{"198.51.100.1"},
		AAAA:        []string{"2001:db8::1"},
		APrivate:    []string{"192.168.1.1"},
		AAAAPrivate: []string{"fd00::1"},
		RFC:         []string{"192.168.1.1"},
		ULA:         []string{"fd00::1"},
	}
	if err := ValidateGeoAnswerSet(valid, "geo"); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}

	badCases := []struct {
		name string
		set  GeoAnswerSet
	}{
		{"InvalidRFC", GeoAnswerSet{RFC: []string{"fd00::1"}}},
		{"MalformedRFC", GeoAnswerSet{RFC: []string{"192.168.1.256"}}},
		{"InvalidULA", GeoAnswerSet{ULA: []string{"192.168.1.1"}}},
		{"MalformedULA", GeoAnswerSet{ULA: []string{"fd00:::1"}}},
	}
	for _, tt := range badCases {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateGeoAnswerSet(tt.set, "geo"); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestValidateConfigListenFields(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		wantMsg string
	}{
		{"OnlyListen", Config{Listen: "1.2.3.4:53"}, false, ""},
		{"ListenAndListenAddrs", Config{Listen: "1.2.3.4:53", ListenAddrs: []string{"0.0.0.0"}}, true, "listen_addrs"},
		{"ListenAndInterfaces", Config{Listen: "1.2.3.4:53", Interfaces: []string{"eth0"}}, true, "interfaces"},
		{"ListenAddrsAndInterfaces", Config{ListenAddrs: []string{"0.0.0.0"}, Interfaces: []string{"eth0"}}, true, "listen_addrs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("expected error mentioning %q, got %v", tt.wantMsg, err)
			}
		})
	}
}

func TestValidateLightup(t *testing.T) {
	baseZone := func() Zone {
		return Zone{
			Name:      "example.org.",
			NS:        []string{"ns1.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    60,
			TTLAnswer: 20,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
		}
	}

	tests := []struct {
		name    string
		lightup *LightupConfig
		wantErr string
	}{
		{
			name: "Valid",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "2a02:8012:bc57::/48",
				Exclude: []string{"2a02:8012:bc57:1::/64", "2a02:8012:bc57:2::/64"},
			},
		},
		{
			name: "ValidFamiliesShape",
			lightup: &LightupConfig{
				Enabled:  true,
				Reverse:  true,
				Strategy: "hash",
				Families: []LightupFamily{{
					Family:      "ipv6",
					Class:       "public",
					Prefix:      "2a02:8012:bc57::/48",
					RespondAAAA: true,
					RespondPTR:  true,
					Exclude:     []string{"2a02:8012:bc57:1::/64"},
				}},
			},
		},
		{
			name: "MissingPrefix",
			lightup: &LightupConfig{
				Enabled: true,
			},
			wantErr: "prefix is required",
		},
		{
			name: "InvalidPrefix",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "not-a-cidr",
			},
			wantErr: "invalid CIDR",
		},
		{
			name: "IPv4PrefixRejected",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "192.0.2.0/24",
			},
			wantErr: "is not IPv6",
		},
		{
			name: "InvalidExclude",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "2a02:8012:bc57::/48",
				Exclude: []string{"bad"},
			},
			wantErr: "exclude[0]",
		},
		{
			name: "ExcludeOutsidePrefix",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "2a02:8012:bc57::/48",
				Exclude: []string{"2a02:8012:bc58::/64"},
			},
			wantErr: "outside prefix",
		},
		{
			name: "ExcludeBroaderThanPrefix",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "2a02:8012:bc57::/48",
				Exclude: []string{"2a02:8012::/32"},
			},
			wantErr: "outside prefix",
		},
		{
			name: "OverlappingExcludes",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "2a02:8012:bc57::/48",
				Exclude: []string{"2a02:8012:bc57:1::/64", "2a02:8012:bc57:1::/80"},
			},
			wantErr: "overlaps",
		},
		{
			name: "MixedLegacyAndFamiliesRejected",
			lightup: &LightupConfig{
				Enabled: true,
				Prefix:  "2a02:8012:bc57::/48",
				Families: []LightupFamily{{
					Family: "ipv6",
					Prefix: "2a02:8012:bc57::/48",
				}},
			},
			wantErr: "cannot be combined",
		},
		{
			name: "MultipleFamiliesAllowed",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{
					{Family: "ipv6", Prefix: "2a02:8012:bc57::/48"},
					{Family: "ipv4", Class: "private", Prefix: "172.16.0.0/24", RespondA: true},
				},
			},
		},
		{
			name: "InvalidFamilyTypeRejected",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{{
					Family: "bogus",
					Prefix: "2a02:8012:bc57::/48",
				}},
			},
			wantErr: "unsupported value",
		},
		{
			name: "IPv4FamilyAllowsPrivateClass",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{{
					Family:   "ipv4",
					Class:    "private",
					Prefix:   "172.16.0.0/24",
					RespondA: true,
					Exclude:  []string{"172.16.0.1/32", "172.16.0.2/32"},
				}},
			},
		},
		{
			name: "IPv4FamilyRejectsIPv6Prefix",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{{
					Family:   "ipv4",
					Class:    "private",
					Prefix:   "fd00::/64",
					RespondA: true,
				}},
			},
			wantErr: "is not IPv4",
		},
		{
			name: "IPv4FamilyRejectsIPv6Exclude",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{{
					Family:   "ipv4",
					Class:    "private",
					Prefix:   "172.16.0.0/24",
					RespondA: true,
					Exclude:  []string{"fd00::1/128"},
				}},
			},
			wantErr: "is not IPv4",
		},
		{
			name: "IPv6FamilyRejectsRespondA",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{{
					Family:   "ipv6",
					Prefix:   "2a02:8012:bc57::/48",
					RespondA: true,
				}},
			},
			wantErr: "respond_a",
		},
		{
			name: "InvalidStrategyRejected",
			lightup: &LightupConfig{
				Enabled:  true,
				Strategy: "random",
				Prefix:   "2a02:8012:bc57::/48",
			},
			wantErr: "strategy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := baseZone()
			z.Lightup = tt.lightup
			err := ValidateZone(&z)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateZone() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidatePTRRecord(t *testing.T) {
	z := Zone{
		Name:      "2.0.192.in-addr.arpa.",
		NS:        []string{"ns1.example.org."},
		Admin:     "hostmaster.example.org.",
		TTLSOA:    60,
		TTLAnswer: 20,
		Refresh:   60,
		Retry:     30,
		Expire:    600,
		Minttl:    60,
		PTR:       []PTRRecord{{Name: "@", PTR: "ptr.example.org."}},
	}
	if err := ValidateZone(&z); err != nil {
		t.Fatalf("valid PTR zone rejected: %v", err)
	}

	z.PTR = []PTRRecord{{Name: "@", PTR: ""}}
	if err := ValidateZone(&z); err == nil {
		t.Fatalf("expected invalid PTR target to fail validation")
	}
}

func TestValidatePools(t *testing.T) {
	baseZone := func() Zone {
		return Zone{
			Name:      "example.org.",
			NS:        []string{"ns1.example.org."},
			Admin:     "hostmaster.example.org.",
			TTLSOA:    60,
			TTLAnswer: 20,
			Refresh:   60,
			Retry:     30,
			Expire:    600,
			Minttl:    60,
		}
	}

	tests := []struct {
		name    string
		zone    func() Zone
		wantErr string
	}{
		{
			name: "ValidNamedGeoPool",
			zone: func() Zone {
				z := baseZone()
				z.Pools = []Pool{
					{Name: "eu-v6", Family: "ipv6", Class: "public", Role: "primary", Members: []IPAddr{{IP: "2001:db8::1"}}},
					{Name: "us-v4", Family: "ipv4", Class: "public", Role: "secondary", Members: []IPAddr{{IP: "198.51.100.1"}}},
				}
				z.Geo = &GeoPolicy{Named: []NamedGeoPolicy{{Name: "eu-v6", Policy: GeoTierPolicy{AllowContinents: []string{"EU"}}}}}
				return z
			},
		},
		{
			name: "MissingPoolMembersRejected",
			zone: func() Zone {
				z := baseZone()
				z.Pools = []Pool{{Name: "eu-v6", Family: "ipv6"}}
				return z
			},
			wantErr: "members is required",
		},
		{
			name: "WrongFamilyMemberRejected",
			zone: func() Zone {
				z := baseZone()
				z.Pools = []Pool{{Name: "bad", Family: "ipv4", Members: []IPAddr{{IP: "2001:db8::1"}}}}
				return z
			},
			wantErr: "is not IPv4",
		},
		{
			name: "UnknownGeoPoolRejected",
			zone: func() Zone {
				z := baseZone()
				z.Pools = []Pool{{Name: "eu-v6", Family: "ipv6", Members: []IPAddr{{IP: "2001:db8::1"}}}}
				z.Geo = &GeoPolicy{Named: []NamedGeoPolicy{{Name: "missing", Policy: GeoTierPolicy{AllowAll: true}}}}
				return z
			},
			wantErr: "unknown pool",
		},
		{
			name: "HostGeoPoolRejectedWhenMissing",
			zone: func() Zone {
				z := baseZone()
				z.Hosts = []Host{{
					Name:  "app",
					Pools: []Pool{{Name: "app-v6", Family: "ipv6", Members: []IPAddr{{IP: "2001:db8::10"}}}},
					Geo:   &GeoPolicy{Named: []NamedGeoPolicy{{Name: "missing", Policy: GeoTierPolicy{AllowAll: true}}}},
				}}
				return z
			},
			wantErr: "hosts[0].geo[missing]: unknown pool",
		},
		{
			name: "HostOutsideZoneRejected",
			zone: func() Zone {
				z := baseZone()
				z.Hosts = []Host{{
					Name:  "app.example.net.",
					Pools: []Pool{{Name: "app-v6", Family: "ipv6", Members: []IPAddr{{IP: "2001:db8::10"}}}},
				}}
				return z
			},
			wantErr: "outside zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := tt.zone()
			err := ValidateZone(&z)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateZone() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateDiscovery(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "ValidDiscovery",
			cfg: Config{
				Discovery: &DiscoveryConfig{
					CatalogZone: "_catalog.example.org.",
					Masters:     []string{"[2001:db8::53]:53"},
					XFRSource:   "2001:db8::54",
					TSIG: &TSIGZoneConfig{Keys: []TSIGKey{{
						Name:         "cluster-xfr.",
						Secret:       "c2VjcmV0c2VjcmV0c2VjcmV0",
						AllowXFRFrom: []string{"2001:db8::/64"},
					}}},
				},
			},
		},
		{
			name: "MastersRequireCatalog",
			cfg: Config{
				Discovery: &DiscoveryConfig{
					Masters: []string{"[2001:db8::53]:53"},
				},
			},
			wantErr: "discovery.catalog_zone",
		},
		{
			name: "InvalidDiscoveryCIDRRejected",
			cfg: Config{
				Discovery: &DiscoveryConfig{
					CatalogZone: "_catalog.example.org.",
					TSIG: &TSIGZoneConfig{Keys: []TSIGKey{{
						Name:         "cluster-xfr.",
						AllowXFRFrom: []string{"2001:db8::/129"},
					}}},
				},
			},
			wantErr: "discovery.tsig.keys[0].allow_xfr_from[0]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(&tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateConfig() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
