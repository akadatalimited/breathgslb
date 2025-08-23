//go:build tools
// +build tools

package main

import (
	"bufio"
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
	"os"
	"runtime"
	"strings"
	"time"
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

func main() {
	email := flag.String("email", "", "licensee email")
	build := flag.String("build", "", "build date (YYYY-MM-DD)")
	osFlag := flag.String("os", "", "target operating system (optional, case-insensitive)")
	expiry := flag.String("expiry", "", "license expiry (YYYY-MM-DD or 'never')")
	supportExpiry := flag.String("supportExpiry", "", "support expiry (YYYY-MM-DD)")
	customerType := flag.String("customerType", "", "customer type")
	supported := flag.Bool("supported", false, "support contract active")
	ltype := flag.String("type", "", "license preset (trial, standard, supported)")
	cfgPath := flag.String("config", "", "path to JSON config file")
	send := flag.Bool("send", false, "email license key to requester")
	smtpServer := flag.String("smtp", "localhost:25", "SMTP server address")
	from := flag.String("from", "", "from email address")
	flag.Parse()

	var cfg licensePayload
	if strings.TrimSpace(*cfgPath) != "" {
		b, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatalf("read config: %v", err)
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Fatalf("parse config: %v", err)
		}
	}

	if strings.TrimSpace(*email) == "" {
		*email = cfg.Email
	}
	if strings.TrimSpace(*build) == "" {
		*build = cfg.Build
	}
	if strings.TrimSpace(*expiry) == "" {
		*expiry = cfg.Expiry
	}
	if strings.TrimSpace(*supportExpiry) == "" {
		*supportExpiry = cfg.SupportExpiry
	}
	if !*supported {
		*supported = cfg.Supported
	}
	if strings.TrimSpace(*customerType) == "" {
		*customerType = cfg.CustomerType
	}
	if strings.TrimSpace(*osFlag) == "" {
		*osFlag = cfg.OS
	}

	switch strings.ToLower(*ltype) {
	case "trial":
		if strings.TrimSpace(*expiry) == "" {
			*expiry = time.Now().AddDate(0, 0, 30).Format("2006-01-02")
		}
		*supported = false
	case "standard":
		if strings.TrimSpace(*expiry) == "" {
			*expiry = "never"
		}
		*supported = false
	case "supported":
		if strings.TrimSpace(*expiry) == "" {
			*expiry = "never"
		}
		*supported = true
		if strings.TrimSpace(*supportExpiry) == "" {
			*supportExpiry = time.Now().AddDate(1, 0, 0).Format("2006-01-02")
		}
	}

	reader := bufio.NewReader(os.Stdin)
	if strings.TrimSpace(*email) == "" {
		fmt.Print("Email: ")
		in, _ := reader.ReadString('\n')
		*email = strings.TrimSpace(in)
	}
	if strings.TrimSpace(*build) == "" {
		fmt.Print("Build date (YYYY-MM-DD): ")
		in, _ := reader.ReadString('\n')
		*build = strings.TrimSpace(in)
	}
	if strings.TrimSpace(*expiry) == "" {
		fmt.Print("Expiry (YYYY-MM-DD or 'never'): ")
		in, _ := reader.ReadString('\n')
		*expiry = strings.TrimSpace(in)
		if *expiry == "" {
			*expiry = "never"
		}
	}
	if !*supported {
		fmt.Print("Support contract (y/N): ")
		in, _ := reader.ReadString('\n')
		in = strings.ToLower(strings.TrimSpace(in))
		if in == "y" || in == "yes" {
			*supported = true
		}
	}
	if *supported && strings.TrimSpace(*supportExpiry) == "" {
		fmt.Print("Support expiry (YYYY-MM-DD): ")
		in, _ := reader.ReadString('\n')
		*supportExpiry = strings.TrimSpace(in)
	}

	if strings.TrimSpace(*email) == "" || strings.TrimSpace(*build) == "" {
		log.Fatal("email and build fields are required")
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

	osVal := *osFlag
	if strings.TrimSpace(osVal) == "" {
		osVal = runtime.GOOS
	}
	osVal = baseOS(osVal)

	lp := licensePayload{
		Build:         *build,
		OS:            osVal,
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
	fmt.Println("hint: enter the key at runtime; supply the payload to the server via the -license-payload flag or build option")

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
