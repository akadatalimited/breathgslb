//go:build windows

package main

import (
	"log"
	"os"
	"os/signal"
)

func handleSignals(cfgPath string) {
	_ = cfgPath
	log.Printf("configuration reload is unsupported on this platform")
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	s := <-sigc
	log.Printf("signal %v: shutting down", s)
	shutdown()
}
