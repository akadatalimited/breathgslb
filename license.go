package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type licensePayload struct {
	Build  string `json:"build"`
	OS     string `json:"os"`
	Email  string `json:"email"`
	Salt   string `json:"salt"`
	Expiry string `json:"expiry"`
}

// validateLicense decrypts an AES-256 encrypted payload using key and validates
// the license against the compiled build OS and build date. If the license is
// valid, the key is written to /etc/breathgslb/license.
func validateLicense(key string, payload []byte) error {
	k := []byte(key)
	if len(k) != 32 {
		return fmt.Errorf("invalid key length")
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
	if lp.OS != buildOS {
		return fmt.Errorf("os mismatch")
	}
	if lp.Build != buildDate {
		return fmt.Errorf("build mismatch")
	}
	buildTime, err := time.Parse("2006-01-02", buildDate)
	if err != nil {
		return fmt.Errorf("invalid build date: %w", err)
	}
	expiryTime, err := time.Parse("2006-01-02", lp.Expiry)
	if err != nil {
		return fmt.Errorf("invalid expiry: %w", err)
	}
	if expiryTime.Before(buildTime) || expiryTime.After(buildTime.Add(30*24*time.Hour)) {
		return fmt.Errorf("expiry out of range")
	}
	if err := os.MkdirAll("/etc/breathgslb", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/breathgslb/license", []byte(key), 0600); err != nil {
		return err
	}
	return nil
}
