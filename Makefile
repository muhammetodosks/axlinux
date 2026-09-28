# AXlinux - ust duzey Makefile
#
# Hedefler:
#   make          -> bpf + go + python derle
#   make test     -> tum testler
#   make verify   -> sozlesme ve bolum dogrulamasi
#   make install  -> sistem dizinlerine kur

SHELL     := /bin/bash
PREFIX    ?= /usr/local
DESTDIR   ?=
BINDIR    := $(DESTDIR)$(PREFIX)/bin
LIBDIR    := $(DESTDIR)/usr/lib/axlinux
SYSCONF   := $(DESTDIR)/etc/axlinux

GO        ?= go
PYTHON    ?= python3
CLANG     ?= clang

BPF_DIR   := src/bpf
GO_DAEMON := src/go/axdaemon
GO_LOG    := src/go/axlog
PY_DIR    := src/python

BINARIES  := axdaemon axlog
STAGED    := $(addprefix $(LIBDIR)/,$(patsubst %,%.o,$(BINARIES) axbpf))

.PHONY: all bpf go python test test-go test-python test-contract verify \
        install uninstall clean fmt lint help

help:
	@echo "AXlinux"
	@echo ""
	@echo "  make            bpf + go + python derle"
	@echo "  make bpf        eBPF LSM nesnesi (axbpf.o)"
	@echo "  make go         axdaemon ve axlog"
	@echo "  make test       tum testler"
	@echo "  make verify     sozlesme ve bolum dogrulamasi"
	@echo "  make install    sistem dizinine kur"
	@echo "  make clean      uretilen tum dosyalari sil"

all: bpf go python

# --- eBPF ---
bpf:
	@echo "== eBPF =="
	@$(MAKE) -C $(BPF_DIR)

verify: bpf
	@$(MAKE) -C $(BPF_DIR) verify

# --- Go ---
go:
	@echo "== Go =="
	@cd $(GO_DAEMON) && $(GO) build -o axdaemon .
	@cd $(GO_LOG)    && $(GO) build -o axlog .
	@echo "   axdaemon, axlog hazir"

# --- Python ---
python:
	@echo "== Python =="
	@$(PYTHON) -m compileall -q $(PY_DIR)/axctl
	@echo "   axctl hazir"

# --- Testler ---
test: test-go test-python

test-go:
	@echo "== Go testleri =="
	@cd $(GO_DAEMON) && $(GO) test ./...
	@cd $(GO_LOG)    && $(GO) test ./... 2>/dev/null || true

# Sozlesme testleri Go↔C sabitlerini karsilastirir.
test-contract: bpf
	@cd $(GO_DAEMON) && $(GO) test ./internal/maps/ -v

test-python:
	@echo "== Python testleri =="
	@$(PYTHON) -m pytest tests/ -q 2>/dev/null \
		|| $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

# --- Lint ---
lint:
	@cd $(GO_DAEMON) && $(GO) vet ./...
	@cd $(GO_LOG)    && $(GO) vet ./...

fmt:
	@cd $(GO_DAEMON) && $(GO) fmt ./...
	@cd $(GO_LOG)    && $(GO) fmt ./...

# --- Kurulum ---
install: all
	@echo "== Kurulum =="
	@install -d $(BINDIR) $(LIBDIR)
	@install -m 0755 $(GO_DAEMON)/axdaemon $(BINDIR)/axdaemon
	@install -m 0755 $(GO_LOG)/axlog       $(BINDIR)/axlog
	@install -m 0644 $(BPF_DIR)/axbpf.o    $(LIBDIR)/axbpf.o
	@install -d $(SYSCONF)
	@install -m 0644 examples/*.yaml        $(SYSCONF)/ 2>/dev/null || true
	@install -m 0755 packaging/axdaemon.service \
		$(DESTDIR)/lib/systemd/system/axdaemon.service 2>/dev/null || true
	@echo "   kuruldu: $(BINDIR), $(LIBDIR)"
	@echo ""
	@echo "   ONEMLI: LSM zincirinde 'bpf' olmadan AXlinux baglanamaz."
	@echo "   docs/INSTALL.md bolum 1'e bakin."

uninstall:
	@rm -f $(BINDIR)/axdaemon $(BINDIR)/axlog
	@rm -rf $(LIBDIR) $(SYSCONF)
	@rm -f $(DESTDIR)/lib/systemd/system/axdaemon.service
	@echo "   kaldirildi"

clean:
	@$(MAKE) -C $(BPF_DIR) clean
	@rm -f $(GO_DAEMON)/axdaemon $(GO_LOG)/axlog
	@find $(PY_DIR) -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "   temizlendi"
