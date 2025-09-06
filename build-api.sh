#!/bin/bash

# Build script for BreathGSLB API server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building BreathGSLB API server...${NC}"

# Create build directory if it doesn't exist
mkdir -p build

# Build the API server
echo -e "${YELLOW}Compiling API server...${NC}"
go build -o build/breathgslb-api \
    -ldflags "-X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    ./src/api_main.go ./src/api_server.go ./src/api_handlers.go

# Check if build was successful
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    echo -e "${GREEN}API server binary located at: build/breathgslb-api${NC}"
    
    # Display file information
    ls -lh build/breathgslb-api
    
    # Display usage information
    echo -e "\n${YELLOW}Usage:${NC}"
    echo -e "  ${GREEN}./build/breathgslb-api${NC}                          # Start with default config"
    echo -e "  ${GREEN}./build/breathgslb-api -config /path/to/config${NC}  # Start with custom config"
    echo -e "  ${GREEN}./build/breathgslb-api -help${NC}                    # Show help"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi