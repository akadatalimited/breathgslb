package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	_ "modernc.org/sqlite"
)

func generateKey() (string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	if len(key) > 32 {
		key = key[:32]
	}
	return key, nil
}

func main() {
	dbPath := flag.String("db", "", "path to sqlite database file")
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("-db is required")
	}
	if flag.NArg() < 1 {
		log.Fatalf("usage: %s -db path [list|revoke|regen] ...", os.Args[0])
	}
	cmd := flag.Arg(0)
	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()
	switch cmd {
	case "list":
		rows, err := db.Query(`SELECT u.email, l.key, l.license_expiry, l.support_expiry, l.support_level FROM licenses l JOIN users u ON l.user_id=u.id`)
		if err != nil {
			log.Fatalf("list: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var email, key, licExp, supExp, level string
			if err := rows.Scan(&email, &key, &licExp, &supExp, &level); err != nil {
				log.Fatalf("scan: %v", err)
			}
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", email, key, licExp, supExp, level)
		}
		if err := rows.Err(); err != nil {
			log.Fatalf("rows: %v", err)
		}
	case "revoke":
		if flag.NArg() < 2 {
			log.Fatal("usage: licensectl -db path revoke <key>")
		}
		key := flag.Arg(1)
		res, err := db.Exec(`DELETE FROM licenses WHERE key=?`, key)
		if err != nil {
			log.Fatalf("revoke: %v", err)
		}
		n, err := res.RowsAffected()
		if err == nil && n == 0 {
			log.Fatalf("revoke: no such key")
		}
	case "regen":
		if flag.NArg() < 2 {
			log.Fatal("usage: licensectl -db path regen <key>")
		}
		oldKey := flag.Arg(1)
		newKey, err := generateKey()
		if err != nil {
			log.Fatalf("generate key: %v", err)
		}
		res, err := db.Exec(`UPDATE licenses SET key=? WHERE key=?`, newKey, oldKey)
		if err != nil {
			log.Fatalf("regen: %v", err)
		}
		n, err := res.RowsAffected()
		if err == nil && n == 0 {
			log.Fatalf("regen: no such key")
		}
		fmt.Println(newKey)
	default:
		log.Fatalf("unknown command %s", cmd)
	}
}
