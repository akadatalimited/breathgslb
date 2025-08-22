//go:build windows

package main

import "io"

func setupSyslogLogging() (io.WriteCloser, error) {
	return nil, nil
}
