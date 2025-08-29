package config

import (
	"strings"

	"github.com/miekg/dns"
)

// TSIGSecretMap builds a map of TSIG key names to secrets from all configured zones.
func TSIGSecretMap(cfg *Config) map[string]string {
	secrets := make(map[string]string)
	if cfg == nil {
		return nil
	}
	for _, z := range cfg.Zones {
		if z.TSIG == nil {
			continue
		}
		for _, k := range z.TSIG.Keys {
			name := dns.Fqdn(strings.ToLower(k.Name))
			secrets[name] = k.Secret
		}
	}
	if len(secrets) == 0 {
		return nil
	}
	return secrets
}
