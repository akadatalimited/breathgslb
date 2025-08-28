package healthcheck

import (
	"net/http"
	"testing"

	"github.com/akadatalimited/breathgslb/src/config"
)

func TestEffectiveDefaults(t *testing.T) {
	h := Effective("example.org.", nil)
	if h.Kind != config.HKHTTP {
		t.Fatalf("expected kind http got %v", h.Kind)
	}
	if h.Port != 443 {
		t.Fatalf("expected port 443 got %d", h.Port)
	}
	if h.Scheme != "https" {
		t.Fatalf("expected https scheme got %s", h.Scheme)
	}
	if h.Method != http.MethodGet {
		t.Fatalf("expected GET method got %s", h.Method)
	}
	if h.Path != "/health" {
		t.Fatalf("expected default path /health got %s", h.Path)
	}
	if h.HostHeader != "example.org" {
		t.Fatalf("expected host header example.org got %s", h.HostHeader)
	}
	if h.SNI != "example.org" {
		t.Fatalf("expected SNI example.org got %s", h.SNI)
	}
}

func TestEffectiveOverride(t *testing.T) {
	override := &config.HealthConfig{
		Kind:       config.HKTCP,
		Scheme:     "http",
		Method:     http.MethodPost,
		Port:       8443,
		HostHeader: "override.example",
		Path:       "/status",
		SNI:        "sni.example",
		ALPN:       "h2",
	}
	h := Effective("example.org.", override)
	if h.Kind != config.HKTCP {
		t.Fatalf("expected kind tcp got %v", h.Kind)
	}
	if h.Port != 8443 {
		t.Fatalf("expected port 8443 got %d", h.Port)
	}
	if h.Scheme != "http" {
		t.Fatalf("expected scheme http got %s", h.Scheme)
	}
	if h.Method != http.MethodPost {
		t.Fatalf("expected method POST got %s", h.Method)
	}
	if h.Path != "/status" {
		t.Fatalf("expected path /status got %s", h.Path)
	}
	if h.HostHeader != "override.example" {
		t.Fatalf("expected host header override.example got %s", h.HostHeader)
	}
	if h.SNI != "sni.example" {
		t.Fatalf("expected SNI sni.example got %s", h.SNI)
	}
	if h.ALPN != "h2" {
		t.Fatalf("expected ALPN h2 got %s", h.ALPN)
	}
}
