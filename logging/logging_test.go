package logging

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/akadatalimited/breathgslb/config"
)

func TestSetupCreatesLogFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test: relies on Unix file permissions")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.log")
	cfg := &config.Config{LogFile: path}

	origFlags := log.Flags()
	origPrefix := log.Prefix()
	origOutput := log.Writer()
	defer func() {
		log.SetFlags(origFlags)
		log.SetPrefix(origPrefix)
		log.SetOutput(origOutput)
	}()

	w := Setup(cfg)
	if w == nil {
		t.Fatalf("Setup returned nil writer")
	}
	defer w.Close()

	log.Print("hello")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Fatalf("expected log file to contain message, got %q", string(data))
	}
}

func TestReopenSwitchesLogFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test: relies on Unix file permissions")
	}
	tmp := t.TempDir()
	first := filepath.Join(tmp, "first.log")
	cfg := &config.Config{LogFile: first}

	origFlags := log.Flags()
	origPrefix := log.Prefix()
	origOutput := log.Writer()
	defer func() {
		log.SetFlags(origFlags)
		log.SetPrefix(origPrefix)
		log.SetOutput(origOutput)
	}()

	w1 := Setup(cfg)
	if w1 != nil {
		w1.Close()
	}

	second := filepath.Join(tmp, "second.log")
	cfg.LogFile = second
	w2 := Reopen(cfg)
	if w2 == nil {
		t.Fatalf("Reopen returned nil writer")
	}
	defer w2.Close()

	log.Print("second")
	data, err := os.ReadFile(second)
	if err != nil {
		t.Fatalf("reading reopened log file: %v", err)
	}
	if !strings.Contains(string(data), "second") {
		t.Fatalf("expected reopened log file to contain message, got %q", string(data))
	}
}
