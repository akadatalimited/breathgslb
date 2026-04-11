package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLightitupDemoConfig(t *testing.T) {
	srcDir := filepath.Clean(filepath.Join("..", "..", "demo", "lightitup"))
	tempDir := t.TempDir()
	zonesDir := filepath.Join(tempDir, "zones")
	reverseDir := filepath.Join(tempDir, "reverse")
	zonesSecondaryDir := filepath.Join(tempDir, "zones-secondary")
	reverseSecondaryDir := filepath.Join(tempDir, "reverse-secondary")
	tsigDir := filepath.Join(tempDir, "tsig")
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll zones: %v", err)
	}
	if err := os.MkdirAll(reverseDir, 0o755); err != nil {
		t.Fatalf("MkdirAll reverse: %v", err)
	}
	if err := os.MkdirAll(zonesSecondaryDir, 0o755); err != nil {
		t.Fatalf("MkdirAll zones-secondary: %v", err)
	}
	if err := os.MkdirAll(reverseSecondaryDir, 0o755); err != nil {
		t.Fatalf("MkdirAll reverse-secondary: %v", err)
	}
	if err := os.MkdirAll(tsigDir, 0o755); err != nil {
		t.Fatalf("MkdirAll tsig: %v", err)
	}

	zoneFiles, err := filepath.Glob(filepath.Join(srcDir, "zones", "*.fwd.yaml"))
	if err != nil {
		t.Fatalf("Glob zones: %v", err)
	}
	for _, src := range zoneFiles {
		dst := filepath.Join(zonesDir, filepath.Base(src))
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", dst, err)
		}
	}
	reverseFiles, err := filepath.Glob(filepath.Join(srcDir, "reverse", "*.rev.yaml"))
	if err != nil {
		t.Fatalf("Glob reverse: %v", err)
	}
	for _, src := range reverseFiles {
		dst := filepath.Join(reverseDir, filepath.Base(src))
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", dst, err)
		}
	}
	zoneFiles, err = filepath.Glob(filepath.Join(srcDir, "zones-secondary", "*.fwd.yaml"))
	if err != nil {
		t.Fatalf("Glob zones-secondary: %v", err)
	}
	for _, src := range zoneFiles {
		dst := filepath.Join(zonesSecondaryDir, filepath.Base(src))
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", dst, err)
		}
	}
	reverseFiles, err = filepath.Glob(filepath.Join(srcDir, "reverse-secondary", "*.rev.yaml"))
	if err != nil {
		t.Fatalf("Glob reverse-secondary: %v", err)
	}
	for _, src := range reverseFiles {
		dst := filepath.Join(reverseSecondaryDir, filepath.Base(src))
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", dst, err)
		}
	}

	for _, tc := range []struct {
		name          string
		configName    string
		expectedServe map[string]string
		wantZonesMin  int
	}{
		{
			name:       "primary",
			configName: "config.yaml",
			wantZonesMin: 3,
			expectedServe: map[string]string{
				"lightitup.zerodns.co.uk.": "primary",
			},
		},
		{
			name:       "secondary",
			configName: "config.gslb2.yaml",
			wantZonesMin: 0,
			expectedServe: map[string]string{},
		},
	} {
		configSrc := filepath.Join(srcDir, tc.configName)
		data, err := os.ReadFile(configSrc)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", tc.configName, err)
		}
		cfgText := string(data)
		cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/zones-secondary", zonesSecondaryDir)
		cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/reverse-secondary", reverseSecondaryDir)
		cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/zones", zonesDir)
		cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/reverse", reverseDir)
		cfgText = strings.ReplaceAll(cfgText, "/etc/breathgslb/tsig", tsigDir)

		cfgPath := filepath.Join(tempDir, tc.configName)
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", tc.configName, err)
		}

		c, err := Load(cfgPath)
		if err != nil {
			t.Fatalf("Load(%q) error = %v", cfgPath, err)
		}
		if c.GeoIP == nil || c.GeoIP.Database == "" {
			t.Fatalf("%s: expected demo GeoIP config, got %#v", tc.name, c.GeoIP)
		}
		if tc.name == "primary" {
			if !c.API || c.APIListen != 9443 || c.APIToken != "/etc/breathgslb/api.token" || c.APICert != "/etc/breathgslb/api.crt" || c.APIKey != "/etc/breathgslb/api.key" {
				t.Fatalf("%s: expected demo API config, got api=%v listen=%d token=%q cert=%q key=%q", tc.name, c.API, c.APIListen, c.APIToken, c.APICert, c.APIKey)
			}
		}
		if c.Discovery == nil || c.Discovery.CatalogZone == "" {
			t.Fatalf("%s: expected demo discovery config, got %#v", tc.name, c.Discovery)
		}
		if len(c.Zones) < tc.wantZonesMin {
			t.Fatalf("%s: expected at least %d demo zones, got %d", tc.name, tc.wantZonesMin, len(c.Zones))
		}
		if tc.name == "secondary" {
			if len(c.Discovery.Masters) == 0 {
				t.Fatalf("%s: expected discovery masters, got %#v", tc.name, c.Discovery)
			}
			if c.Discovery.XFRSource == "" {
				t.Fatalf("%s: expected discovery xfr_source, got %#v", tc.name, c.Discovery)
			}
			continue
		}
		var sawForward, sawReverseV6, sawReverseV4 bool
		for _, z := range c.Zones {
			if want, ok := tc.expectedServe[z.Name]; ok && z.Serve != want {
				t.Fatalf("%s: zone %s serve=%q want %q", tc.name, z.Name, z.Serve, want)
			}
			switch z.Name {
			case "lightitup.zerodns.co.uk.":
				sawForward = true
				if z.Geo == nil {
					t.Fatalf("%s: expected demo forward zone geo policy", tc.name)
				}
				if len(z.Pools) == 0 {
					t.Fatalf("%s: expected demo forward zone pools, got %#v", tc.name, z.Pools)
				}
				if len(z.Hosts) == 0 {
					t.Fatalf("%s: expected demo forward zone hosts, got %#v", tc.name, z.Hosts)
				}
				if z.Hosts[0].Health == nil {
					t.Fatalf("%s: expected demo forward host health override, got %#v", tc.name, z.Hosts[0])
				}
				if len(z.Geo.Named) == 0 {
					t.Fatalf("%s: expected demo forward zone named geo policies, got %#v", tc.name, z.Geo)
				}
			case "3.5.3.5.7.5.c.b.2.1.0.8.2.0.a.2.ip6.arpa.":
				sawReverseV6 = true
				if tc.name == "primary" && len(z.PTR) < 4 {
					t.Fatalf("expected populated reverse demo zone, got %#v", z.PTR)
				}
			case "0.16.172.in-addr.arpa.":
				sawReverseV4 = true
				if tc.name == "primary" && len(z.PTR) < 2 {
					t.Fatalf("expected populated IPv4 reverse demo zone, got %#v", z.PTR)
				}
			}
		}
		if !sawForward || !sawReverseV6 || !sawReverseV4 {
			t.Fatalf("%s: expected forward, IPv6 reverse, and IPv4 reverse demo zones, got %#v", tc.name, c.Zones)
		}
	}
}
