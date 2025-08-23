package dnsserver

import (
	"reflect"
	"testing"

	"github.com/akadatalimited/breathgslb/config"
)

func TestDerivePort(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "53"},
		{"127.0.0.1:8053", "8053"},
		{"[::1]:8054", "8054"},
		{"192.0.2.1", "53"},
	}
	for _, tt := range tests {
		if got := derivePort(tt.in); got != tt.want {
			t.Errorf("derivePort(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTargetsFromConfigListenAddrs(t *testing.T) {
	cfg := &config.Config{
		Listen:      "0.0.0.0:53",
		ListenAddrs: []string{"1.2.3.4", "[2001:db8::1]:54"},
	}
	got := targetsFromConfig(cfg)
	want := []bindTarget{
		{netw: "udp4", addr: "1.2.3.4:53"},
		{netw: "tcp4", addr: "1.2.3.4:53"},
		{netw: "udp6", addr: "[2001:db8::1]:54"},
		{netw: "tcp6", addr: "[2001:db8::1]:54"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targetsFromConfig() = %#v, want %#v", got, want)
	}
}

func TestTargetsFromConfigDefault(t *testing.T) {
	cfg := &config.Config{}
	got := targetsFromConfig(cfg)
	want := []bindTarget{
		{netw: "udp4", addr: "0.0.0.0:53"},
		{netw: "udp6", addr: "[::]:53"},
		{netw: "tcp4", addr: "0.0.0.0:53"},
		{netw: "tcp6", addr: "[::]:53"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targetsFromConfig() = %#v, want %#v", got, want)
	}
}
