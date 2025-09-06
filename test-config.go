package main

import (
	"fmt"
	"log"

	"github.com/akadatalimited/breathgslb/src/config"
)

func main() {
	// Load the test configuration
	cfg, err := config.Load("../test-config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Setup defaults
	config.SetupDefaults(cfg)

	// Print the CPU limiting options
	fmt.Printf("Max CPU Cores: %d\n", cfg.MaxCPUCores)
	fmt.Printf("Max Threads: %d\n", cfg.MaxThreads)
	
	// Verify they are properly set
	if cfg.MaxCPUCores == 2 && cfg.MaxThreads == 8 {
		fmt.Println("SUCCESS: CPU limiting options are correctly parsed!")
	} else {
		fmt.Println("ERROR: CPU limiting options are not correctly parsed!")
	}
}