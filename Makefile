# --- Project
BINARY      ?= breathgslb
PKG         ?= github.com/akadatalimited/breathgslb
WEB_BINARY  ?= web/web

# --- Tooling / flags
GO          ?= go
CGO_ENABLED ?= 1
GOFLAGS     ?=
# Disable automatic VCS stamping which can fail when the repository
# metadata is unavailable (e.g. during installs on systems like Alpine).
# The build still embeds version information via BUILD_LDFLAGS, so this
# only suppresses Go's own VCS checks.
GOFLAGS     += -buildvcs=false
LDFLAGS     ?= -s -w

# Vendor by default (NOVENDOR=1 to bypass)
ifeq ($(NOVENDOR),1)
MODFLAG :=
	else
MODFLAG := -mod=vendor
endif

# Version injection
VERSION_TXT := $(shell cat version.txt)
GIT_COMMIT  := $(shell git rev-parse --short HEAD)
BUILD_OS    := $(shell uname -s)
BUILD_LDFLAGS := $(LDFLAGS) -X 'main.version=$(VERSION_TXT).$(GIT_COMMIT)' -X 'main.buildOS=$(BUILD_OS)'

# Paths
PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
SYSD_PREFIX ?= /etc/systemd/system
ORC_PREFIX  ?= /etc/init.d
LOGDIR      ?= /var/log/breathgslb
CFGDIR      ?= /etc/breathgslb
KEYDIR      ?= $(CFGDIR)/keys
ZONEDIR     ?= $(CFGDIR)/zones
REVERSEDIR  ?= $(CFGDIR)/reverse
DISTDIR     ?= dist
MANDIR      ?= $(PREFIX)/share/man
MAN5DIR     ?= $(MANDIR)/man5
MAN8DIR     ?= $(MANDIR)/man8

# Utils
MKDIR_P := mkdir -p
TAR     ?= tar
ZIP     ?= zip -9
SHA256  := $(shell command -v sha256sum 2>/dev/null || command -v shasum 2>/dev/null)
SHA256FLAGS := $(shell [ "$$(basename $(SHA256))" = "shasum" ] && echo -a || echo )

# Documentation paths
DOC_PDF := doc/breathgslb.pdf

# -------------------- standard targets --------------------
.PHONY: all build vendor clean fmt vet test help web \
        release release-linux release-musl release-macos release-freebsd release-bsd release-windows \
        package docs licensegen install install-man install-systemd install-openrc uninstall

all: build

docs: $(DOC_PDF)

help:
	@echo "Available targets:"
	@echo "  build            build the $(BINARY) binary"
	@echo "  test             run tests with the race detector"
	@echo "  release          build release binaries for all supported platforms"
	@echo "  release-linux    build release binaries for Linux"
	@echo "  release-musl     build static Linux binaries (musl)"
	@echo "  release-macos    build release binaries for macOS"
	@echo "  release-freebsd  build release binaries for FreeBSD"
	@echo "  release-bsd      build release binaries for OpenBSD and NetBSD"
	@echo "  release-windows  build release binaries for Windows"
	@echo "  package          archive release binaries and generate checksums"

build:
	@echo "==> building ($(BINARY)) with GOFLAGS='$(GOFLAGS)' CGO_ENABLED=$(CGO_ENABLED)"
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(BINARY)

web:
	@echo "==> building ($(WEB_BINARY)) with GOFLAGS='$(GOFLAGS)' CGO_ENABLED=$(CGO_ENABLED)"
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" -mod=mod $(GOFLAGS) -o $(WEB_BINARY) ./web

vendor:
	$(GO) mod tidy
	$(GO) mod vendor

clean:
	rm -f $(BINARY)
	rm -rf $(DISTDIR) $(DOC_PDF) doc/breathgslb.md

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

licensegen:
	$(GO) build -tags tools ./cmd/licensegen

# -------------------- documentation --------------------
doc/man/%.md: man/% scripts/man2md.py
	scripts/man2md.py $< $@

doc/breathgslb.md: doc/breathgslb-book.md doc/man/breathgslb.md doc/man/breathgslb.conf.md
	sed -e '/{{breathgslb_manual}}/r doc/man/breathgslb.md' -e '/{{breathgslb_manual}}/d' -e '/{{breathgslb_conf_manual}}/r doc/man/breathgslb.conf.md' -e '/{{breathgslb_conf_manual}}/d' doc/breathgslb-book.md > $@

$(DOC_PDF): doc/breathgslb.md scripts/md2pdf.py
	scripts/md2pdf.py doc/breathgslb.md $(DOC_PDF)

# -------------------- release matrices --------------------
release: clean release-linux release-musl release-macos release-freebsd release-bsd release-windows

release-linux:
	$(MKDIR_P) $(DISTDIR)
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-amd64
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-arm64

# Static-ish MUSL builds for Alpine (no cgo)
release-musl:
	$(MKDIR_P) $(DISTDIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -tags netgo -trimpath -ldflags "$(BUILD_LDFLAGS) -extldflags '-static'" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-amd64-musl
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -tags netgo -trimpath -ldflags "$(BUILD_LDFLAGS) -extldflags '-static'" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-linux-arm64-musl

release-macos:
	$(MKDIR_P) $(DISTDIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-darwin-amd64
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-darwin-arm64

release-freebsd:
	$(MKDIR_P) $(DISTDIR)
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-freebsd-amd64
	GOOS=freebsd GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-freebsd-arm64

release-bsd:
	$(MKDIR_P) $(DISTDIR)
	GOOS=openbsd GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-openbsd-amd64
	GOOS=openbsd GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-openbsd-arm64
	GOOS=netbsd  GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-netbsd-amd64
	GOOS=netbsd  GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-netbsd-arm64

release-windows:
	$(MKDIR_P) $(DISTDIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-windows-amd64.exe
	GOOS=windows GOARCH=arm64 CGO_ENABLED=1 $(GO) build -trimpath -ldflags "$(BUILD_LDFLAGS)" $(MODFLAG) $(GOFLAGS) -o $(DISTDIR)/$(BINARY)-windows-arm64.exe

# -------------------- packaging --------------------
package: release $(DOC_PDF)
	@echo "==> packaging archives"
	cd $(DISTDIR) && \
	for f in *; do \
	base="$${f%.*}"; \
	case "$$f" in \
	*.exe) $(ZIP) "$$f.zip" "$$f" >/dev/null && rm -f "$$f";; \
	*.pdf) ;; \
	*)     $(TAR) -czf "$$f.tar.gz" "$$f" && rm -f "$$f";; \
	esac; \
	done
	cp $(DOC_PDF) $(DISTDIR)/
	@# checksums
	@if [ -n "$(SHA256)" ]; then \
	(cd $(DISTDIR) && $(SHA256) $(SHA256FLAGS) * > SHA256SUMS); \
	echo "==> wrote $(DISTDIR)/SHA256SUMS"; \
	else \
	echo "!! sha256 tool not found; skipping sums"; \
	fi

# -------------------- install targets --------------------
install: build install-man
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BINARY) $(DESTDIR)$(BINDIR)/$(BINARY)
	# helper scripts
	if [ -d scripts ]; then \
	  install -d $(DESTDIR)$(BINDIR); \
	  for f in scripts/*; do \
	    [ -f $$f ] && install -m 0755 $$f $(DESTDIR)$(BINDIR)/$$(basename $$f); \
	done; \
	fi
	# dirs used by the service
	install -d -m 0750 $(DESTDIR)$(CFGDIR)
	install -d -m 0755 $(DESTDIR)$(KEYDIR)
	install -d -m 0755 $(DESTDIR)$(LOGDIR)
	[ -z "$(ZONEDIR)" ] || install -d -m 0755 $(DESTDIR)$(ZONEDIR)
	[ -z "$(REVERSEDIR)" ] || install -d -m 0755 $(DESTDIR)$(REVERSEDIR)

install-man:
	install -d $(DESTDIR)$(MAN8DIR) $(DESTDIR)$(MAN5DIR)
	install -m 0644 man/breathgslb.8 $(DESTDIR)$(MAN8DIR)/breathgslb.8
	install -m 0644 man/breathgslb.conf.5 $(DESTDIR)$(MAN5DIR)/breathgslb.conf.5
	ln -sf breathgslb.conf.5 $(DESTDIR)$(MAN5DIR)/breathgslb.5

install-systemd: install
	install -d $(DESTDIR)$(SYSD_PREFIX)
	install -m 0644 services/systemd/$(BINARY).service $(DESTDIR)$(SYSD_PREFIX)/$(BINARY).service
	@echo "Reload/enable with:"
	@echo "  systemctl daemon-reload && systemctl enable --now $(BINARY)"

# NOTE: ensure the OpenRC script in services/init.d is named '$(BINARY)'
install-openrc: install
	install -d $(DESTDIR)$(ORC_PREFIX)
	install -m 0755 services/init.d/$(BINARY) $(DESTDIR)$(ORC_PREFIX)/$(BINARY)
	@echo "Add to default runlevel with:"
	@echo "  rc-update add $(BINARY) default && rc-service $(BINARY) start"

uninstall:
	- systemctl stop $(BINARY) 2>/dev/null || true
	- rc-service $(BINARY) stop 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY)
	if [ -d scripts ]; then \
	  for f in scripts/*; do rm -f $(DESTDIR)$(BINDIR)/$$(basename $$f); done; \
	fi
	rm -f $(DESTDIR)$(SYSD_PREFIX)/$(BINARY).service
	rm -f $(DESTDIR)$(ORC_PREFIX)/$(BINARY) || true
