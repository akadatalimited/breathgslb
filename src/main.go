package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/akadatalimited/breathgslb/src/dnsserver"
	"github.com/akadatalimited/breathgslb/src/logging"
)

// Version and build information set at link time.
var version string

func main() {
	cfgPath := flag.String("config", "/etc/breathgslb/config.yaml", "path to YAML configuration")
	debugPprof := flag.Bool("debug-pprof", false, "enable pprof on localhost:6060")
	apiListen := flag.String("api-listen", "", "override API listen address")
	apiToken := flag.String("api-token", "", "override API token or token file")
	apiCert := flag.String("api-cert", "", "override API certificate path")
	apiKey := flag.String("api-key", "", "override API key path")
	_ = flag.String("supervisor", "", "reserved for supervisor integrations")
	flag.Parse()

	serialDir = filepath.Join(filepath.Dir(filepath.Clean(*cfgPath)), "serials")
	cfg, _, err := loadRuntimeConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config %s: %v", *cfgPath, err)
	}

	if *apiListen != "" {
		cfg.API = true
		cfg.APIListen = 0
	}
	if *apiToken != "" {
		cfg.API = true
		cfg.APIToken = *apiToken
	}
	if *apiCert != "" {
		cfg.API = true
		cfg.APICert = *apiCert
	}
	if *apiKey != "" {
		cfg.API = true
		cfg.APIKey = *apiKey
	}

	logW := logging.Setup(cfg)
	current.logW = logW

	if *debugPprof {
		go func() {
			if err := http.ListenAndServe("localhost:6060", nil); err != nil {
				log.Printf("pprof listener stopped: %v", err)
			}
		}()
	}

	geo := newGeoResolver(cfg.GeoIP)
	sup = newSupervisor()
	mux, auths := buildMux(cfg, geo, sup, nil)
	rt := &router{}
	rt.inner.Store(mux)
	current.cfg = cfg
	current.cfgSig = mustRuntimeConfigSignature(cfg)
	current.rt = rt
	current.auths = auths
	current.geo = geo

	secrets := collectTSIGSecrets(cfg)
	dnsserver.StartListeners(rt, cfg, cfg.MaxWorkers, secrets)

	if cfg.API {
		apiCfg, err := runtimeAPIConfig(cfg, *apiListen)
		if err != nil {
			log.Fatalf("api config: %v", err)
		}
		apiMain, err := NewAPIMain(apiCfg)
		if err != nil {
			log.Fatalf("start api: %v", err)
		}
		go func() {
			if err := apiMain.Start(); err != nil {
				log.Printf("api stopped: %v", err)
			}
		}()
	}

	go autoReloadLoop(context.Background(), *cfgPath)

	handleSignals(*cfgPath)
	shutdown()
}

func mustRuntimeConfigSignature(cfg *Config) string {
	sig, err := runtimeConfigSignature(cfg)
	if err != nil {
		log.Fatalf("runtime config signature: %v", err)
	}
	return sig
}

func collectTSIGSecrets(cfg *Config) map[string]string {
	secrets := make(map[string]string)
	if cfg.Discovery != nil && cfg.Discovery.TSIG != nil {
		for _, k := range cfg.Discovery.TSIG.Keys {
			if k.Name == "" || k.Secret == "" {
				continue
			}
			secrets[ensureDot(k.Name)] = k.Secret
		}
	}
	for _, z := range cfg.Zones {
		if z.TSIG == nil {
			continue
		}
		for _, k := range z.TSIG.Keys {
			if k.Name == "" || k.Secret == "" {
				continue
			}
			secrets[ensureDot(k.Name)] = k.Secret
		}
	}
	if len(secrets) == 0 {
		return nil
	}
	return secrets
}

func runtimeAPIConfig(cfg *Config, apiListenOverride string) (*APIConfig, error) {
	apiCfg, err := LoadAPIConfig("")
	if err != nil {
		return nil, err
	}
	if apiListenOverride != "" {
		apiCfg.Listen = apiListenOverride
	} else if cfg.APIListen > 0 {
		addrs := apiAddrs(cfg.APIInterface, cfg.APIListen)
		if len(addrs) > 0 {
			apiCfg.Listen = addrs[0]
		}
	}
	if cfg.APIToken != "" {
		apiCfg.TokenFile = cfg.APIToken
	}
	if cfg.APICert != "" {
		apiCfg.CertFile = cfg.APICert
	}
	if cfg.APIKey != "" {
		apiCfg.KeyFile = cfg.APIKey
	}
	return apiCfg, nil
}

func shutdown() {
	for _, auth := range current.auths {
		if auth != nil && auth.cancel != nil {
			auth.cancel()
		}
	}
	if current.geo != nil {
		current.geo.Close()
		current.geo = nil
	}
	if current.logW != nil {
		_ = current.logW.Close()
		current.logW = nil
	}
	os.Exit(0)
}
