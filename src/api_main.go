package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
)

// APIMain is the main API server struct
type APIMain struct {
	server   *http.Server
	router   *mux.Router
	handlers *APIHandlers
	api      *APIServer
	config   *APIConfig
	shutdown chan struct{}
}

// APIConfig holds the API server configuration
type APIConfig struct {
	Listen      string   `yaml:"listen"`
	Interface   []string `yaml:"interface,omitempty"`
	CertFile    string   `yaml:"cert_file"`
	KeyFile     string   `yaml:"key_file"`
	TokenFile   string   `yaml:"token_file"`
	ManagerUUID string   `yaml:"manager_uuid"`
	JWTSecret   string   `yaml:"jwt_secret"`
	AESKey      string   `yaml:"aes_key"`
}

// LoadAPIConfig loads the API configuration from a file
func LoadAPIConfig(path string) (*APIConfig, error) {
	// For now, we'll create a default config
	config := &APIConfig{
		Listen:    ":8443",
		CertFile:  "/etc/breathgslb/api.crt",
		KeyFile:   "/etc/breathgslb/api.key",
		TokenFile: "/etc/breathgslb/api.token",
	}

	// Generate manager UUID if not set
	if config.ManagerUUID == "" {
		config.ManagerUUID = generateUUID()
	}

	// Generate JWT secret if not set
	if config.JWTSecret == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %v", err)
		}
		config.JWTSecret = base64.StdEncoding.EncodeToString(secret)
	}

	// Generate AES key if not set
	if config.AESKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate AES key: %v", err)
		}
		config.AESKey = base64.StdEncoding.EncodeToString(key)
	}

	return config, nil
}

// NewAPIMain creates a new API server instance
func NewAPIMain(config *APIConfig) (*APIMain, error) {
	// Decode JWT secret
	jwtSecret, err := base64.StdEncoding.DecodeString(config.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT secret: %v", err)
	}

	// Decode AES key
	aesKey, err := base64.StdEncoding.DecodeString(config.AESKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %v", err)
	}

	// Create API server
	api := NewAPIServer(config.ManagerUUID, jwtSecret, aesKey)

	// Create API handlers
	handlers := NewAPIHandlers(api)

	// Create HTTP router
	router := mux.NewRouter()

	// Create HTTP server
	server := &http.Server{
		Addr:    config.Listen,
		Handler: router,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Create API main
	apiMain := &APIMain{
		server:   server,
		router:   router,
		handlers: handlers,
		api:      api,
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Register routes
	apiMain.registerRoutes()

	return apiMain, nil
}

// registerRoutes registers all API routes
func (a *APIMain) registerRoutes() {
	// Public routes (no authentication required)
	a.router.HandleFunc("/health", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.HealthCheckHandler))).Methods("GET")
	a.router.HandleFunc("/auth/token", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.AuthTokenHandler))).Methods("POST")

	// Protected routes (authentication required)
	// Zones
	a.router.HandleFunc("/zones", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.ZoneListHandler)))).Methods("GET")
	a.router.HandleFunc("/zones", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.ZoneCreateHandler)))).Methods("POST")
	a.router.HandleFunc("/zones/{zone}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.ZoneGetHandler)))).Methods("GET")
	a.router.HandleFunc("/zones/{zone}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.ZoneUpdateHandler)))).Methods("PUT")
	a.router.HandleFunc("/zones/{zone}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.ZoneDeleteHandler)))).Methods("DELETE")

	// Records
	a.router.HandleFunc("/zones/{zone}/records", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.RecordListHandler)))).Methods("GET")
	a.router.HandleFunc("/zones/{zone}/records", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.RecordCreateHandler)))).Methods("POST")
	a.router.HandleFunc("/zones/{zone}/records/{record}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.RecordUpdateHandler)))).Methods("PUT")
	a.router.HandleFunc("/zones/{zone}/records/{record}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.RecordDeleteHandler)))).Methods("DELETE")

	// Users (manager only)
	a.router.HandleFunc("/users", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.PermissionMiddleware("admin", a.handlers.UserListHandler))))).Methods("GET")
	a.router.HandleFunc("/users", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.PermissionMiddleware("admin", a.handlers.UserCreateHandler))))).Methods("POST")
	a.router.HandleFunc("/users/{user}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.PermissionMiddleware("admin", a.handlers.UserGetHandler))))).Methods("GET")
	a.router.HandleFunc("/users/{user}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.PermissionMiddleware("admin", a.handlers.UserUpdateHandler))))).Methods("PUT")
	a.router.HandleFunc("/users/{user}", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.PermissionMiddleware("admin", a.handlers.UserDeleteHandler))))).Methods("DELETE")

	// Stats
	a.router.HandleFunc("/stats", a.handlers.CORSHandler(a.handlers.LoggingHandler(a.handlers.RateLimitHandler(a.handlers.AuthMiddleware(a.handlers.StatsHandler)))).Methods("GET")

	// Catch-all for 404
	a.router.PathPrefix("/").HandlerFunc(a.handlers.NotFoundHandler)
	a.router.MethodNotAllowedHandler = http.HandlerFunc(a.handlers.MethodNotAllowedHandler)
}

// Start starts the API server
func (a *APIMain) Start() error {
	log.Printf("Starting BreathGSLB API server on %s", a.config.Listen)

	// Start HTTP server
	go func() {
		if err := a.server.ListenAndServeTLS(a.config.CertFile, a.config.KeyFile); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Println("Received shutdown signal")
	case <-a.shutdown:
		log.Println("Received shutdown request")
	}

	// Gracefully shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := a.server.Shutdown(ctx); err != nil {
		log.Printf("API server shutdown error: %v", err)
		return err
	}

	log.Println("API server stopped")
	return nil
}

// Stop stops the API server
func (a *APIMain) Stop() {
	close(a.shutdown)
}

// generateUUID generates a random UUID
func generateUUID() string {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		panic(err)
	}
	// Set the version (4) and variant bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

// Main function for the API server
func main() {
	var configPath string
	var showHelp bool

	flag.StringVar(&configPath, "config", "api_config.yaml", "path to API configuration file")
	flag.StringVar(&configPath, "c", "api_config.yaml", "path to API configuration file")
	flag.BoolVar(&showHelp, "help", false, "show help")
	flag.BoolVar(&showHelp, "h", false, "show help")

	flag.Parse()

	if showHelp {
		fmt.Println("BreathGSLB API Server")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		return
	}

	// Load configuration
	config, err := LoadAPIConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load API configuration: %v", err)
	}

	// Create API server
	apiMain, err := NewAPIMain(config)
	if err != nil {
		log.Fatalf("Failed to create API server: %v", err)
	}

	// Start API server
	if err := apiMain.Start(); err != nil {
		log.Fatalf("API server failed: %v", err)
	}

	log.Println("BreathGSLB API server shutdown complete")
}