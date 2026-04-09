package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads and validates configuration from path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	loaded := map[string]bool{}
	if err := loadZoneDir(&cfg, cfg.ZonesDir, loaded); err != nil {
		return nil, err
	}
	if err := loadZoneDir(&cfg, cfg.ReverseDir, loaded); err != nil {
		return nil, err
	}
	if err := ValidateConfig(&cfg); err != nil {
		return nil, err
	}
	if err := GenerateReverseZones(&cfg); err != nil {
		return nil, err
	}
	if err := ValidateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func loadZoneDir(cfg *Config, dir string, loaded map[string]bool) error {
	if dir == "" {
		return nil
	}
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".fwd.yaml") && !strings.HasSuffix(info.Name(), ".rev.yaml") {
			return nil
		}
		path = filepath.Clean(path)
		if loaded[path] {
			return nil
		}
		zb, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var zs []Zone
		if err := yaml.Unmarshal(zb, &zs); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		cfg.Zones = append(cfg.Zones, zs...)
		loaded[path] = true
		return nil
	})
}

// SetupDefaults applies default values to unspecified configuration fields.
func SetupDefaults(cfg *Config) {
	if cfg.TimeoutSec == 0 {
		cfg.TimeoutSec = 5
	}
	if cfg.IntervalSec == 0 {
		cfg.IntervalSec = 8
	}
	if cfg.Rise == 0 {
		cfg.Rise = 2
	}
	if cfg.Fall == 0 {
		cfg.Fall = 4
	}
	if cfg.EDNSBuf == 0 {
		cfg.EDNSBuf = 1232
	}
	if cfg.MaxRecords < 0 {
		cfg.MaxRecords = 0
	}
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = runtime.NumCPU()
	}
	if cfg.JitterMs < 0 {
		cfg.JitterMs = 0
	}
	if cfg.CooldownSec == 0 {
		cfg.CooldownSec = 25
	}
	if cfg.DNS64Prefix == "" {
		cfg.DNS64Prefix = "64:ff9b::"
	}
	if cfg.API && cfg.APIListen == 0 {
		cfg.APIListen = 9443
	}
	if cfg.LogFile == "" && !cfg.LogSyslog {
		cfg.LogFile = "/var/log/breathgslb/breathgslb.log"
	}
	if cfg.GeoIP != nil {
		if cfg.GeoIP.PreferField == "" {
			cfg.GeoIP.PreferField = "registered"
		}
		if cfg.GeoIP.CacheTTLSec == 0 {
			cfg.GeoIP.CacheTTLSec = 600
		}
	}
	// CPU limiting defaults
	if cfg.MaxCPUCores <= 0 {
		cfg.MaxCPUCores = runtime.NumCPU()
	}
	if cfg.MaxThreads <= 0 {
		// Default to 4 threads per CPU core
		cfg.MaxThreads = cfg.MaxCPUCores * 4
	}
}

// GenerateTSIGKeys populates missing TSIG secrets and optionally writes them to disk.
func GenerateTSIGKeys(cfg *Config) {
	if cfg.TSIG == nil {
		return
	}
	var keyDir string
	if cfg.TSIG.Path != "" {
		keyDir = cfg.TSIG.Path
		_ = os.MkdirAll(keyDir, 0o755)
	}
	for zi := range cfg.Zones {
		z := &cfg.Zones[zi]
		if z.TSIG == nil {
			continue
		}
		defAlg := z.TSIG.DefaultAlgorithm
		if defAlg == "" {
			defAlg = "hmac-sha256"
		}
		seed := ""
		if z.TSIG.SeedEnv != "" {
			seed = os.Getenv(z.TSIG.SeedEnv)
		}
		for ki := range z.TSIG.Keys {
			k := &z.TSIG.Keys[ki]
			if k.Algorithm == "" {
				k.Algorithm = defAlg
			}
			if k.Secret == "" {
				if seed != "" {
					k.Secret = DeriveTSIGSecret(seed, k.Name, z.TSIG.Epoch)
				} else {
					k.Secret = randomTSIGSecret()
				}
			}
			if keyDir != "" {
				saveTSIGKey(keyDir, *k)
			}
		}
	}
}

func DeriveTSIGSecret(seed, name string, epoch int) string {
	h := hmac.New(sha256.New, []byte(seed))
	h.Write([]byte(fmt.Sprintf("%s|%d", name, epoch)))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func randomTSIGSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func saveTSIGKey(dir string, k TSIGKey) {
	name := strings.TrimSuffix(k.Name, ".")
	path := filepath.Join(dir, name+".key")
	content := fmt.Sprintf("key \"%s\" {\n    algorithm %s;\n    secret \"%s\";\n};\n", k.Name, k.Algorithm, k.Secret)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		fmt.Printf("tsig: write %s: %v\n", path, err)
	}
}
