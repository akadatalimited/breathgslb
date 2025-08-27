package main

// buildOS is injected by main.go via ldflags when the full server is compiled.
// Building this file standalone (e.g. `go build license.go`) will fail due to
// the missing symbol.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

type licensePayload struct {
	OS            string `json:"os"`
	Email         string `json:"email"`
	Salt          string `json:"salt"`
	SupportExpiry string `json:"support_expiry"`
	Supported     bool   `json:"supported"`
	CustomerType  string `json:"customer_type"`
}

var supportActive bool
var supportExpiry time.Time
var buildOS string

func baseOS(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "linux"):
		return "linux"
	case strings.HasPrefix(s, "darwin"):
		return "darwin"
	case strings.HasPrefix(s, "windows"):
		return "windows"
	case strings.Contains(s, "bsd"):
		return "bsd"
	default:
		return s
	}
}

// validateLicense decrypts an AES-256 encrypted payload using key and validates
// the license against the compiled build OS. If the license is valid, the key
// is written to /etc/breathgslb/license.
func validateLicense(key string, payload []byte) error {
	k := []byte(key)
	if len(k) != 32 {
		return fmt.Errorf("invalid key length")
	}
	if len(payload) == 0 {
		return fmt.Errorf("license payload missing")
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ns := aead.NonceSize()
	if len(payload) < ns {
		return fmt.Errorf("payload too short")
	}
	nonce := payload[:ns]
	ciphertext := payload[ns:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	var lp licensePayload
	if err := json.Unmarshal(plaintext, &lp); err != nil {
		return err
	}
	binOS := buildOS
	if binOS == "" {
		binOS = runtime.GOOS
	}
	if !strings.EqualFold(baseOS(lp.OS), baseOS(binOS)) {
		return fmt.Errorf("os mismatch")
	}

	supportActive = false
	supportExpiry = time.Time{}
	if lp.Supported {
		se, err := time.Parse("2006-01-02", lp.SupportExpiry)
		if err != nil {
			return fmt.Errorf("invalid support expiry: %w", err)
		}
		supportExpiry = se
		if time.Now().Before(se) {
			supportActive = true
		}
	}
	if err := os.MkdirAll("/etc/breathgslb", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/breathgslb/license", []byte(key), 0600); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/breathgslb/license.payload", []byte(base64.StdEncoding.EncodeToString(payload)), 0600); err != nil {
		return err
	}
	status := "inactive"
	if supportActive {
		status = "active"
	}
	if err := os.WriteFile("/etc/breathgslb/support", []byte(status), 0600); err != nil {
		return err
	}
	return nil
}

func isSupportActive() bool {
	return supportActive
}

func supportStatus() (bool, int) {
	days := 0
	if !supportExpiry.IsZero() {
		days = int(time.Until(supportExpiry).Hours() / 24)
		if days < 0 {
			days = 0
		}
	}
	return supportActive, days
}
