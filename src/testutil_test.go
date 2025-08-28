package main

import (
	"net"
	"testing"
)

// ensureIPv4 verifies that the current environment supports binding to an IPv4
// address. If IPv4 is unavailable, the test is skipped.
func ensureIPv4(t *testing.T) {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("IPv4 not available: %v", err)
	}
	l.Close()
}
