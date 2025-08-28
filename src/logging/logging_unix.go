//go:build !windows

package logging

import (
	"io"
	"log"
	"log/syslog"
	"os"
)

func setupSyslogLogging() (io.WriteCloser, error) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "breathgslb")
	if err != nil {
		return nil, err
	}
	mw := io.MultiWriter(os.Stderr, w)
	log.SetOutput(mw)
	log.SetFlags(0)
	log.SetPrefix("")
	log.Printf("logging to syslog")
	return w, nil
}
