package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

type Config struct {
	DB struct {
		Driver string `yaml:"driver"`
		DSN    string `yaml:"dsn"`
	} `yaml:"db"`
	Admin struct {
		Email string `yaml:"email"`
	} `yaml:"admin"`
	Server struct {
		Interface string `yaml:"interface"`
		Port      int    `yaml:"port"`
		IP        string `yaml:"ip"`
	} `yaml:"server"`
}

var (
	cfg Config
	db  *sql.DB
)

func loadConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return err
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.IP == "" && cfg.Server.Interface != "" {
		ifi, err := net.InterfaceByName(cfg.Server.Interface)
		if err != nil {
			return err
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return err
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
				continue
			}
			cfg.Server.IP = ip.String()
			break
		}
	}
	return nil
}

func initDB() error {
	var err error
	db, err = sql.Open(cfg.DB.Driver, cfg.DB.DSN)
	if err != nil {
		return err
	}
	auto := "AUTOINCREMENT"
	if cfg.DB.Driver == "mysql" {
		auto = "AUTO_INCREMENT"
	}
	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY %s,
        email TEXT UNIQUE,
        verified BOOLEAN,
        token TEXT
    );`, auto))
	if err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY %s,
        user_id INTEGER,
        key TEXT,
        license_expiry TEXT,
        support_expiry TEXT,
        support_level TEXT
    );`, auto))
	if err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS tiers (
        id INTEGER PRIMARY KEY %s,
        name TEXT
    );`, auto))
	return err
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sendEmail(to, subject, body string) {
	log.Printf("send email to %s: %s\n%s", to, subject, body)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	token := generateToken()
	_, err := db.Exec("INSERT INTO users(email, verified, token) VALUES(?,0,?)", email, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendEmail(email, "Verify your account", fmt.Sprintf("Visit /verify?token=%s", token))
	fmt.Fprintln(w, "verification email sent")
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	res, err := db.Exec("UPDATE users SET verified=1 WHERE token=?", token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	fmt.Fprintln(w, "account verified")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	var verified bool
	err := db.QueryRow("SELECT verified FROM users WHERE email=?", email).Scan(&verified)
	if err != nil || !verified {
		http.Error(w, "invalid email or not verified", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "email", Value: email, Path: "/"})
	fmt.Fprintln(w, "logged in")
}

func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie("email")
		if err != nil {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("email")
		if err != nil || c.Value != cfg.Admin.Email {
			http.Error(w, "admin only", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func listLicensesHandler(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("email")
	rows, err := db.Query("SELECT key, license_expiry, support_expiry, support_level FROM licenses l JOIN users u ON l.user_id=u.id WHERE u.email=?", c.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var key, le, se, sl string
		rows.Scan(&key, &le, &se, &sl)
		fmt.Fprintf(w, "%s %s %s %s\n", key, le, se, sl)
	}
}

func requestLicenseHandler(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("email")
	var id int
	err := db.QueryRow("SELECT id FROM users WHERE email=?", c.Value).Scan(&id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := generateToken()
	licExp := time.Now().AddDate(1, 0, 0).Format(time.RFC3339)
	supExp := time.Now().AddDate(0, 6, 0).Format(time.RFC3339)
	_, err = db.Exec("INSERT INTO licenses(user_id,key,license_expiry,support_expiry,support_level) VALUES(?,?,?,?,?)", id, key, licExp, supExp, "email")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendEmail(c.Value, "Your license key", key)
	fmt.Fprintln(w, key)
}

func resendLicenseHandler(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("email")
	key := r.FormValue("key")
	var k string
	err := db.QueryRow("SELECT key FROM licenses l JOIN users u ON l.user_id=u.id WHERE u.email=? AND l.key=?", c.Value, key).Scan(&k)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendEmail(c.Value, "Your license key", k)
	fmt.Fprintln(w, "resent")
}

func adminAccountsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT email, verified FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var email string
		var verified bool
		rows.Scan(&email, &verified)
		fmt.Fprintf(w, "%s %v\n", email, verified)
	}
}

func adminIssueLicenseHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	level := r.FormValue("level")
	var id int
	err := db.QueryRow("SELECT id FROM users WHERE email=?", email).Scan(&id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := generateToken()
	licExp := time.Now().AddDate(1, 0, 0).Format(time.RFC3339)
	supExp := time.Now().AddDate(0, 6, 0).Format(time.RFC3339)
	_, err = db.Exec("INSERT INTO licenses(user_id,key,license_expiry,support_expiry,support_level) VALUES(?,?,?,?,?)", id, key, licExp, supExp, level)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendEmail(email, "Your license key", key)
	fmt.Fprintln(w, key)
}

func adminRenewLicenseHandler(w http.ResponseWriter, r *http.Request) {
	key := r.FormValue("key")
	licExp := time.Now().AddDate(1, 0, 0).Format(time.RFC3339)
	supExp := time.Now().AddDate(0, 6, 0).Format(time.RFC3339)
	res, err := db.Exec("UPDATE licenses SET license_expiry=?, support_expiry=? WHERE key=?", licExp, supExp, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "license not found", http.StatusNotFound)
		return
	}
	var email string
	err = db.QueryRow("SELECT u.email FROM licenses l JOIN users u ON l.user_id=u.id WHERE l.key=?", key).Scan(&email)
	if err == nil {
		sendEmail(email, "Your license has been renewed", key)
	}
	fmt.Fprintln(w, "renewed")
}

func adminRevokeLicenseHandler(w http.ResponseWriter, r *http.Request) {
	key := r.FormValue("key")
	var email string
	err := db.QueryRow("SELECT u.email FROM licenses l JOIN users u ON l.user_id=u.id WHERE l.key=?", key).Scan(&email)
	if err != nil {
		http.Error(w, "license not found", http.StatusNotFound)
		return
	}
	_, err = db.Exec("DELETE FROM licenses WHERE key=?", key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendEmail(email, "Your license has been revoked", key)
	fmt.Fprintln(w, "revoked")
}

func adminCreateTierHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	_, err := db.Exec("INSERT INTO tiers(name) VALUES(?)", name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "tier created")
}

func main() {
	if err := loadConfig("config.yaml"); err != nil {
		log.Fatal(err)
	}
	if err := initDB(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/licenses", requireLogin(listLicensesHandler))
	http.HandleFunc("/license/request", requireLogin(requestLicenseHandler))
	http.HandleFunc("/license/resend", requireLogin(resendLicenseHandler))

	http.HandleFunc("/admin/accounts", requireAdmin(adminAccountsHandler))
	http.HandleFunc("/admin/issue", requireAdmin(adminIssueLicenseHandler))
	http.HandleFunc("/admin/renew", requireAdmin(adminRenewLicenseHandler))
	http.HandleFunc("/admin/revoke", requireAdmin(adminRevokeLicenseHandler))
	http.HandleFunc("/admin/tier", requireAdmin(adminCreateTierHandler))

	addr := net.JoinHostPort(cfg.Server.IP, strconv.Itoa(cfg.Server.Port))
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
