//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func handleSignals(cfgPath string) {
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		s := <-sigc
		switch s {
		case syscall.SIGHUP:
			if err := reload(cfgPath); err != nil {
				log.Printf("reload failed: %v", err)
			} else {
				log.Printf("reloaded configuration")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("signal %v: shutting down", s)
			shutdown()
			return
		}
	}
}
