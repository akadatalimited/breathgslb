//go:build tools
// +build tools

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

type licensePayload struct {
	Build         string `json:"build"`
	OS            string `json:"os"`
	Email         string `json:"email"`
	Salt          string `json:"salt"`
	Expiry        string `json:"expiry"`
	SupportExpiry string `json:"support_expiry"`
	Supported     bool   `json:"supported"`
	CustomerType  string `json:"customer_type"`
}

func main() {
	email := flag.String("email", "", "licensee email")
	build := flag.String("build", "", "build date (YYYY-MM-DD)")
	osFlag := flag.String("os", "", "target operating system")
	expiry := flag.String("expiry", "never", "license expiry (YYYY-MM-DD or 'never')")
	supportExpiry := flag.String("supportExpiry", "", "support expiry (YYYY-MM-DD)")
	customerType := flag.String("customerType", "", "customer type")
	supported := flag.Bool("supported", false, "support contract active")
	send := flag.Bool("send", false, "email license key to requester")
	smtpServer := flag.String("smtp", "localhost:25", "SMTP server address")
	from := flag.String("from", "", "from email address")
	flag.Parse()

	if strings.TrimSpace(*email) == "" || strings.TrimSpace(*build) == "" || strings.TrimSpace(*osFlag) == "" {
		log.Fatal("email, build, and os flags are required")
	}
	if *supported && strings.TrimSpace(*supportExpiry) == "" {
		log.Fatal("supportExpiry required when supported is true")
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Fatalf("generate key: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)[:32]

	saltBytes := make([]byte, 8)
	if _, err := rand.Read(saltBytes); err != nil {
		log.Fatalf("generate salt: %v", err)
	}
	salt := hex.EncodeToString(saltBytes)

	lp := licensePayload{
		Build:         *build,
		OS:            *osFlag,
		Email:         *email,
		Salt:          salt,
		Expiry:        *expiry,
		SupportExpiry: *supportExpiry,
		Supported:     *supported,
		CustomerType:  *customerType,
	}

	plain, err := json.Marshal(lp)
	if err != nil {
		log.Fatalf("marshal payload: %v", err)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalf("new cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("new gcm: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("nonce: %v", err)
	}
	cipherText := aead.Seal(nil, nonce, plain, nil)
	payload := append(nonce, cipherText...)

	fmt.Printf("key: %s\n", key)
	fmt.Printf("payload: %s\n", base64.StdEncoding.EncodeToString(payload))

	if *send {
		if strings.TrimSpace(*from) == "" {
			log.Fatal("from address required when send is true")
		}
		msg := fmt.Sprintf("To: %s\r\nSubject: breathgslb license\r\n\r\nYour license key: %s\r\n", *email, key)
		if err := smtp.SendMail(*smtpServer, nil, *from, []string{*email}, []byte(msg)); err != nil {
			log.Fatalf("send mail: %v", err)
		}
	}
}
