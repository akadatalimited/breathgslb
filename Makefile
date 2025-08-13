# BreathGSLB Makefile
# - Uses vendor/ if present (repro builds). Override with NOVENDOR=1 to bypass.
# - Cross-compile release artifacts (linux/macos/freebsd, amd64/arm64)
# - Install helpers and service files for systemd/OpenRC

# ---- project vars
BINARY      ?= breathgslb
PKG         ?= github.com/akadatalimited/breathgslb
LDFLAGS    ?= -s -w
GOFLAGS    ?=
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
LOGDIR     ?= /var/log/$(BINARY)
KEYDIR     ?= /etc/$(BINARY)/keys
CONFDIR    ?= /etc/$(BINARY)
DISTDIR    ?= dist

# Use vendor by default if vendor/ exists and NOVENDOR not set.
ifneq ($(wildcard vendor),)
ifneq ($(NOVENDOR),1)
  GOFLAGS += -mod=vendor
endif
endif

# CGO default can be overridden; musl builds set CGO=0 below explicitly
CGO_ENABLED ?= 1

# ---- helpers
GO        ?= go
INSTALL   ?= install
RM        ?= rm -f
MKDIR_P   ?= mkdir -p
CP        ?= cp -f

# ---- targets
.PHONY: all build clean vendor test release \
        release-linux release-macos release-freebsd \
        release-musl \
        install install-systemd install-openrc uninstall

all: build

build:
	@echo "==> building ($(BINARY)) with GOFLAGS='$(GOFLAGS)' CGO_ENABLED=$(CGO_ENABLED)"
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(LDFLAGS)" $(GOFLAGS) -o $(BINARY)

clean:
	$(RM) $(BINARY)
	$(RM) -r $(DISTDIR)

vendor:
	@echo "==> tidy + vendor"
	$(GO) mod tidy
	$(GO) mod vendor

test:
	$(GO) test ./...

# --- Release matrices
release: release-linux release-macos release-freebsd

release-linux:
	$(MKDIR_P) $(DISTDIR)
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(LDFLAGS)" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-amd64
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(LDFLAGS)" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-arm64

# Static-ish musl builds for Alpine (no CGO)
release-musl:
	$(MKDIR_P) $(DISTDIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -tags netgo -trimpath -ldflags "$(LDFLAGS) -extldflags '-static'" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-amd64-musl
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -tags netgo -trimpath -ldflags "$(LDFLAGS) -extldflags '-static'" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-arm64-musl

release-macos:
	$(MKDIR_P) $(DISTDIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(LDFLAGS)" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-darwin-amd64
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(LDFLAGS)" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-darwin-arm64

release-freebsd:
	$(MKDIR_P) $(DISTDIR)
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(LDFLAGS)" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-freebsd-amd64
	GOOS=freebsd GOARCH=arm64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(LDFLAGS)" $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-freebsd-arm64

# --- Installers (no user/group creation here; do that in packaging or manually)
install: build
	@echo "==> installing binary + config dirs"
	$(MKDIR_P) $(BINDIR)
	$(INSTALL) -m 0755 $(BINARY) $(BINDIR)/$(BINARY)
	$(MKDIR_P) $(CONFDIR)
	$(MKDIR_P) $(KEYDIR)
	$(MKDIR_P) $(LOGDIR)
	# sample configs/scripts if present
	@if [ -f config.sample.yaml ]; then $(INSTALL) -m 0644 config.sample.yaml $(CONFDIR)/config.sample.yaml; fi
	@if [ -f healthcheck.json ]; then $(INSTALL) -m 0644 healthcheck.json $(CONFDIR)/healthcheck.sample.json; fi
	# helper scripts
	@if [ -d scripts ]; then \
	  for s in scripts/*; do \
	    if [ -f $$s ]; then $(INSTALL) -m 0755 $$s $(BINDIR)/$$(basename $$s); fi; \
	  done \
	fi

install-systemd:
	@echo "==> installing systemd unit"
	$(MKDIR_P) /etc/systemd/system
	@if [ -f services/systemd/$(BINARY).service ]; then \
	   $(INSTALL) -m 0644 services/systemd/$(BINARY).service /etc/systemd/system/$(BINARY).service; \
	   systemctl daemon-reload || true; \
	   echo "Enable with: systemctl enable --now $(BINARY)"; \
	 else \
	   echo "WARN: services/systemd/$(BINARY).service not found"; \
	 fi

install-openrc:
	@echo "==> installing OpenRC script"
	$(MKDIR_P) /etc/init.d
	@if [ -f services/init.d/$(BINARY) ]; then \
	   $(INSTALL) -m 0755 services/init.d/$(BINARY) /etc/init.d/$(BINARY); \
	   echo "Add to default runlevel: rc-update add $(BINARY) default"; \
	   echo "Start: rc-service $(BINARY) start"; \
	 else \
	   echo "WARN: services/init.d/$(BINARY) not found"; \
	 fi

uninstall:
	$(RM) $(BINDIR)/$(BINARY)
	$(RM) /etc/systemd/system/$(BINARY).service
	$(RM) /etc/init.d/$(BINARY)
	@echo "Config left in $(CONFDIR) and logs in $(LOGDIR)"

