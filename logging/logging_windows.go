//go:build windows

package logging

import "io"

func setupSyslogLogging() (io.WriteCloser, error) {
	return nil, nil
}
