package logging

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/akadatalimited/breathgslb/config"
)

// Setup configures logging according to cfg and returns the log writer, if any.
func Setup(cfg *config.Config) io.WriteCloser {
	if cfg.LogSyslog {
		w, err := setupSyslogLogging()
		if err != nil {
			log.Printf("warn: cannot connect to syslog: %v; using stderr only", err)
			return nil
		}
		return w
	}
	path := cfg.LogFile
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("warn: cannot create log dir %s: %v; falling back to ./breathgslb.log", dir, err)
		path = "./breathgslb.log"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("warn: cannot open log file %s: %v; using stderr only", path, err)
		return nil
	}
	mw := io.MultiWriter(os.Stderr, f)
	log.SetOutput(mw)
	log.SetFlags(0)
	log.SetPrefix("")
	log.Printf("logging to %s", path)
	return f
}

// Reopen closes the previous writer and sets up logging again.
func Reopen(cfg *config.Config) io.WriteCloser {
	return Setup(cfg)
}
