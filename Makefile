BINARY=breathgslb
PKG=github.com/akadatalimited/breathgslb
LDFLAGS=-s -w

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)

release:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64

vendor:
	go mod tidy
	go mod vendor
