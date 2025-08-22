//go:build windows

package main

import (
	"context"
	"net"
)

func listenUDP(network, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{}
	return lc.ListenPacket(context.Background(), network, addr)
}
