# Phage — build orchestration.
# Go targets run anywhere; BPF targets require Linux + clang + libbpf headers.

GO        ?= go
CLANG     ?= clang
BIN       ?= bin
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -X main.version=$(VERSION)

# Install layout (override PREFIX/DESTDIR for packaging). phaged finds the
# auxiliary eBPF objects next to the one given with -bpf, so they all live in
# LIBDIR together.
PREFIX     ?= /usr/local
DESTDIR    ?=
BINDIR      := $(DESTDIR)$(PREFIX)/bin
LIBDIR      := $(DESTDIR)$(PREFIX)/lib/phage
SYSCONFDIR  := $(DESTDIR)/etc/phage
UNITDIR     := $(DESTDIR)/etc/systemd/system

# Release packaging. The tarball carries the binaries, the CO-RE eBPF objects,
# a default config, and the unit. (This fork does not consume release tarballs:
# it is built in-house from a pinned commit; see FORK.md.) The version lives in
# a VERSION file inside.
DIST      := dist
DISTNAME  := phage_linux_amd64
SHASUM    := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo 'shasum -a 256')

# Map `uname -m` to the arch macro clang's bpf headers expect (x86_64 -> x86).
UNAME_M   := $(shell uname -m)
BPF_ARCH  := $(if $(filter x86_64,$(UNAME_M)),x86,$(if $(filter aarch64,$(UNAME_M)),arm64,$(UNAME_M)))
# Each *.bpf.c under bpf/programs compiles to its own object in bpf/build.
BPF_SRCS  := $(wildcard bpf/programs/*.bpf.c)
BPF_OBJS  := $(patsubst bpf/programs/%.bpf.c,bpf/build/%.bpf.o,$(BPF_SRCS))

.PHONY: all build daemon cli jail test lint tidy clean bpf gen-vmlinux install uninstall dist release help

all: build ## Build everything (Go only)

build: daemon cli jail ## Build the daemon, the CLI, and the jail tool

daemon: ## Build phaged
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/phaged ./cmd/phaged

cli: ## Build the phage CLI
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/phage ./cmd/phage

jail: ## Build the phage-jail tool
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/phage-jail ./cmd/phage-jail

test: ## Run Go tests
	$(GO) test ./...

lint: ## Vet the Go code
	$(GO) vet ./...

tidy: ## Tidy go.mod
	$(GO) mod tidy

# --- Linux-only below ---------------------------------------------------------

gen-vmlinux: ## Generate bpf/include/vmlinux/vmlinux.h from the running kernel (Linux)
	./scripts/gen/vmlinux.sh

bpf: $(BPF_OBJS) ## Compile every eBPF program with CO-RE (Linux)

bpf/build/%.bpf.o: bpf/programs/%.bpf.c
	@mkdir -p bpf/build
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I bpf/include/vmlinux -I bpf/programs \
		-c $< -o $@
	@llvm-strip -g $@ 2>/dev/null || true
	@echo "built $@"

install: ## Install binaries, eBPF objects, config, and the systemd unit (Linux, root)
	@test -f $(BIN)/phaged || { echo "missing $(BIN)/phaged — run 'make build' first"; exit 1; }
	@test -f bpf/build/sensors.bpf.o || { echo "missing eBPF objects — run 'make bpf' first (needs Linux + clang)"; exit 1; }
	install -d $(BINDIR) $(LIBDIR) $(SYSCONFDIR) $(UNITDIR)
	install -m 0755 $(BIN)/phaged $(BIN)/phage $(BIN)/phage-jail $(BINDIR)/
	install -m 0644 bpf/build/*.bpf.o $(LIBDIR)/
	install -m 0644 deploy/phage.service $(UNITDIR)/phage.service
	@if [ -f $(SYSCONFDIR)/phage.yaml ]; then \
		echo "keeping existing $(SYSCONFDIR)/phage.yaml"; \
	else \
		install -m 0644 configs/phage.example.yaml $(SYSCONFDIR)/phage.yaml; \
		echo "installed default config -> $(SYSCONFDIR)/phage.yaml (mode: learn)"; \
	fi
	@echo ""
	@echo "Installed. Next:"
	@echo "  systemctl daemon-reload"
	@echo "  systemctl enable --now phage      # starts in LEARN mode (acts on nothing)"
	@echo "  journalctl -u phage -f            # watch it learn"

dist: ## Package a release tarball + checksums from the built artifacts (run build + bpf first)
	@test -f $(BIN)/phaged || { echo "missing $(BIN)/phaged — run 'make build' first"; exit 1; }
	@test -f bpf/build/sensors.bpf.o || { echo "missing eBPF objects — run 'make bpf' first"; exit 1; }
	rm -rf $(DIST)/$(DISTNAME) $(DIST)/$(DISTNAME).tar.gz $(DIST)/SHA256SUMS
	mkdir -p $(DIST)/$(DISTNAME)/bpf
	cp $(BIN)/phaged $(BIN)/phage $(BIN)/phage-jail $(DIST)/$(DISTNAME)/
	cp bpf/build/*.bpf.o $(DIST)/$(DISTNAME)/bpf/
	cp deploy/phage.service $(DIST)/$(DISTNAME)/phage.service
	cp configs/phage.example.yaml $(DIST)/$(DISTNAME)/phage.example.yaml
	cp LICENSE $(DIST)/$(DISTNAME)/LICENSE
	echo "$(VERSION)" > $(DIST)/$(DISTNAME)/VERSION
	tar czf $(DIST)/$(DISTNAME).tar.gz -C $(DIST) $(DISTNAME)
	cd $(DIST) && $(SHASUM) $(DISTNAME).tar.gz > SHA256SUMS
	@echo "packaged $(DIST)/$(DISTNAME).tar.gz ($(VERSION))"

release: ## Pinned in-house release: go.mod's Go, CGO_ENABLED=0, -trimpath, -buildvcs, local vmlinux.h, SHA256SUMS (Linux)
	./scripts/build/release.sh

uninstall: ## Remove binaries, eBPF objects, and the unit (keeps /etc/phage and /var/lib/phage)
	rm -f $(BINDIR)/phaged $(BINDIR)/phage $(BINDIR)/phage-jail
	rm -rf $(LIBDIR)
	rm -f $(UNITDIR)/phage.service
	@echo "removed binaries, objects, and unit."
	@echo "kept config ($(SYSCONFDIR)) and state (/var/lib/phage) — 'rm -rf' them to purge."

clean: ## Remove build output
	rm -rf $(BIN) bpf/build/*.o

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
