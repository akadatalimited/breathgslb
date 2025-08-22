package config

import "testing"

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
