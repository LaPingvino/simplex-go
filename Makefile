# simplex-go — Makefile
#
# Build/install kozi-cli (the desktop form of Kozi) and simplex-cli
# (the protocol-debugging tool). Defaults install to ~/.local/bin so no
# sudo is required; override with PREFIX=/usr/local etc.

PREFIX ?= $(HOME)/.local
BINDIR := $(PREFIX)/bin
KOZI   := kozi-cli
SIMPLE := simplex-cli

.PHONY: all build install uninstall test vet clean help

all: build

build:
	@mkdir -p bin
	go build -o bin/$(KOZI)   ./cmd/$(KOZI)
	go build -o bin/$(SIMPLE) ./cmd/$(SIMPLE)
	@echo "Built bin/$(KOZI) and bin/$(SIMPLE)"

install: build
	@install -d $(BINDIR)
	install -m 0755 bin/$(KOZI)   $(BINDIR)/$(KOZI)
	install -m 0755 bin/$(SIMPLE) $(BINDIR)/$(SIMPLE)
	@echo "Installed to $(BINDIR)/{$(KOZI),$(SIMPLE)}"
	@echo "Make sure $(BINDIR) is in your PATH."

uninstall:
	rm -f $(BINDIR)/$(KOZI) $(BINDIR)/$(SIMPLE)
	@echo "Removed $(BINDIR)/{$(KOZI),$(SIMPLE)}"

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin/

help:
	@echo "simplex-go Makefile targets:"
	@echo "  build      Build bin/kozi-cli and bin/simplex-cli"
	@echo "  install    Install both to $(BINDIR) (override with PREFIX=)"
	@echo "  uninstall  Remove installed binaries"
	@echo "  test       Run all Go tests"
	@echo "  vet        Run go vet"
	@echo "  clean      Remove bin/"
	@echo ""
	@echo "Current PREFIX: $(PREFIX)"
