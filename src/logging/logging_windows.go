//go:build windows

package logging

import (
	"io"
	"log"
	"os"

	"golang.org/x/sys/windows/svc/eventlog"
)

type eventLogWriter struct {
	el *eventlog.Log
}

func (w *eventLogWriter) Write(p []byte) (int, error) {
	msg := string(p)
	if err := w.el.Info(1, msg); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *eventLogWriter) Close() error {
	return w.el.Close()
}

func setupSyslogLogging() (io.WriteCloser, error) {
	el, err := eventlog.Open("breathgslb")
	if err != nil {
		if err := eventlog.InstallAsEventCreate("breathgslb", eventlog.Info|eventlog.Warning|eventlog.Error); err != nil {
			return nil, err
		}
		el, err = eventlog.Open("breathgslb")
		if err != nil {
			return nil, err
		}
	}
	w := &eventLogWriter{el}
	mw := io.MultiWriter(os.Stderr, w)
	log.SetOutput(mw)
	log.SetFlags(0)
	log.SetPrefix("")
	log.Printf("logging to Windows event log: breathgslb")
	return w, nil
}
