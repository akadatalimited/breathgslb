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
			name: "MultipleFamiliesRejected",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{
					{Family: "ipv6", Prefix: "2a02:8012:bc57::/48"},
					{Family: "ipv6", Prefix: "fd00::/48"},
				},
			},
			wantErr: "only one family",
		},
		{
			name: "InvalidFamilyTypeRejected",
			lightup: &LightupConfig{
				Enabled: true,
				Families: []LightupFamily{{
					Family: "ipv4",
					Prefix: "2a02:8012:bc57::/48",
				}},
			},
			wantErr: "unsupported value",
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
