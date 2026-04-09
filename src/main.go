package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/akadatalimited/breathgslb/src/config"
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

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config %s: %v", *cfgPath, err)
	}
	config.SetupDefaults(cfg)
	config.GenerateTSIGKeys(cfg)

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
	current.geo = geo
	sup = newSupervisor()
	mux, auths := buildMux(cfg, geo, sup, nil)
	current.cfg = cfg
	current.auths = auths

	secrets := collectTSIGSecrets(cfg)
	dnsserver.StartListeners(mux, cfg, cfg.MaxWorkers, secrets)

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

	handleSignals(*cfgPath)
	shutdown()
}

func collectTSIGSecrets(cfg *Config) map[string]string {
	secrets := make(map[string]string)
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
