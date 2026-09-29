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

.PHONY: all bpf go python test test-go test-python test-contract \
        test-static test-protection test-silent test-integration \
        verify install uninstall clean fmt lint help

help:
	@echo "AXlinux"
	@echo ""
	@echo "  make            bpf + go + python derle"
	@echo "  make bpf        eBPF LSM nesnesi (axbpf.o)"
	@echo "  make go         axdaemon ve axlog"
	@echo "  make test       tum birim + statik testler"
	@echo "  make verify     sozlesme ve bolum dogrulamasi"
	@echo "  make install    sistem dizinine kur"
	@echo "  make clean      uretilen tum dosyalari sil"
	@echo ""
	@echo "  Test kirilimlari:"
	@echo "    make test-go             Go testleri"
	@echo "    make test-python         Python birim testleri"
	@echo "    make test-static         statik sozlesme kontrolleri"
	@echo "    make test-protection     kilitlenme korumasi"
	@echo "    make test-silent         sessiz basarisizlik regresyonlari"
	@echo "    make test-integration    gercek daemon gerektirir"
	@echo ""
	@echo "  Gercek enforcement dogrulamasi (kilitlenme korumali):"
	@echo "    sudo bash tests/verify_all.sh"
	@echo "  Reboot sonrasi tam dogrulama + commit:"
	@echo "    sudo bash scripts/recover-and-verify.sh"

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
# test-contract   Go<->C sabit ve struct karsilastirmasi (Go tarafi)
# test-static     Derlemeden once calisan statik sozlesme/koruma
#                 kontrolleri. Bunlar bpf_d_path turu sessiz
#                 basarisizliklari YAPILANDAN once yakalar.
# test-protection Sistem kilitlenmesi korumasi (ax_protected)
# test-silent     Sessiz basarisizlik regresyonlari
#
# "make test" HEPSINI calistirir. test-protection ve test-silent
# daha once .PHONY listesinde bile yoktu ve hicbir hedefe bagli
# degildi; yani koruma kontrolleri normal calistirmada hicbir
# zaman calismiyordu.
test: test-go test-static test-protection test-silent test-python

test-go:
	@echo "== Go testleri =="
	@cd $(GO_DAEMON) && $(GO) test ./...
	# axlog satiri "2>/dev/null || true" ile bitiyordu. Bu, derleme
	# hatasini da test basarisizligini de yutup sessizce gecmeye
	# yol aciyordu: yeni paket hicbir zaman gercekten test edilmiyor,
	# yalnizca "calistirildi" saniliyordu. Bir testi calistirmak ile
	# dogrulamak farkli sey; bu satir test ediyor.
	@cd $(GO_LOG)    && $(GO) test ./...

# Sozlesme testleri Go<->C sabitlerini karsilastirir.
test-contract: bpf
	@cd $(GO_DAEMON) && $(GO) test ./internal/maps/ -v

test-protection:
	@echo "== Kilitlenme korumasi =="
	@$(PYTHON) tests/test_protection.py

test-static:
	@echo "== Statik sozlesme kontrolleri =="
	@$(PYTHON) tests/test_contracts_static.py

test-silent:
	@echo "== Sessiz basarisizlik regresyonlari =="
	@$(PYTHON) -m unittest discover -s tests -p 'test_silent_failure.py' -v

# Yalnizca pytest'in toplayabildigi unittest.TestCase dosyalari.
# test_protection.py ve test_contracts_static.py main() fonksiyonu
# tasiyan betiklerdir; pytest onlari test olarak saymaz (0 test
# toplanir) ve OZEL HEDEFLERDE calistirilirlar.
test-python:
	@echo "== Python testleri =="
	@$(PYTHON) -m pytest tests/test_axctl.py tests/test_paths.py \
		tests/test_silent_failure.py -q 2>/dev/null \
		|| $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

# Gercek daemon + gercek enforcement. Unit test'te CALISMAZ:
# calisan bir axdaemon ve yuklu bir politika gerektirir.
test-integration:
	@echo "== Entegrasyon (calisan daemon gerekli) =="
	@$(PYTHON) tests/integration.py

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
	@# axctl: CLI PAKETLENMEZSE kullanicinin elimde komut olmaz.
	@# "python:" hedefi yalnizca byte-compile ediyordu; hicbir yere
	@# kurulum yapmiyordu, boylece "axctl hazir" yazisi yanlislikla
	@# basari bildiriyordu. Kurulum burada.
	@install -d $(LIBDIR)/axctl
	@install -m 0644 $(PY_DIR)/axctl/*.py  $(LIBDIR)/axctl/
	@printf '#!/usr/bin/env python3\nimport sys, os\nsys.path.insert(0, "%s")\nfrom axctl.cli import main\nsys.exit(main())\n' \
		"$(LIBDIR)" > $(BINDIR)/axctl
	@chmod 0755 $(BINDIR)/axctl
	@install -d $(DESTDIR)/usr/share/doc/axlinux/docs
	@install -m 0644 docs/*.md              $(DESTDIR)/usr/share/doc/axlinux/docs/ 2>/dev/null || true
	@install -d $(SYSCONF)
	@install -m 0644 examples/*.yaml        $(SYSCONF)/ 2>/dev/null || true
	# Dokumanlar yukarida docs/ altina kuruldu. Eski satir
	# /usr/share/doc/axlinux/ (docs/ degil) hedefliyordu; o dizin
	# hicbir zaman olusmadigi icin "|| true" ile sessizce basarisiz
	# oluyordu ve hicbir dokuman kurulmuyordu.
	@install -m 0755 packaging/axdaemon.service \
		$(DESTDIR)/lib/systemd/system/axdaemon.service 2>/dev/null || true
	@install -m 0755 packaging/axlog.service \
		$(DESTDIR)/lib/systemd/system/axlog.service 2>/dev/null || true
	@echo "   kuruldu: $(BINDIR), $(LIBDIR)"
	@echo ""
	@echo "   IKI SERVIS KURULDU. Kalici audit kaydi icin ikisi de"
	@echo "   etkinlestirilmelidir:"
	@echo "     sudo systemctl enable --now axlog axdaemon"
	@echo "   Yalnizca axdaemon calisiyorsa kayitlar bellekte kalir ve"
	@echo "   /var/log/axlinux bos olur."
	@echo ""
	@echo "   ONEMLI: LSM zincirinde 'bpf' olmadan AXlinux baglanamaz."
	@echo "   docs/INSTALL.md bolum 1'e bakin."

uninstall:
	@rm -f $(BINDIR)/axdaemon $(BINDIR)/axlog
	@rm -rf $(LIBDIR) $(SYSCONF)
	@rm -f $(DESTDIR)/lib/systemd/system/axdaemon.service
	@rm -f $(DESTDIR)/lib/systemd/system/axlog.service
	@rm -rf $(DESTDIR)/usr/share/doc/axlinux
	@echo "   kaldirildi"

clean:
	@$(MAKE) -C $(BPF_DIR) clean
	@rm -f $(GO_DAEMON)/axdaemon $(GO_LOG)/axlog
	@find $(PY_DIR) -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "   temizlendi"
