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

# Go'yu PATH'e guvenerek bulma.
#
# Once dogrudan "go" idi. Bu, docs/INSTALL.md'in oneridigi
# "sudo make install" yolunu bozuyordu: sudo guvenli PATH'i
# (/usr/local/go/bin icermez) uzerinden calistigi icin:
#   /bin/bash: line 1: go: command not found
#   make: *** [Makefile:69: go] Error 127
#
# install.sh Go'yu kurup /usr/local/bin'e bagliyor; make ise
# kurulumdan ONCE de calistigi icin ayni yollari kendisi
# denemeli. GO=... ile disaridan da verilebilir.
GO ?= $(shell command -v go 2>/dev/null || \
        ls /usr/local/go/bin/go 2>/dev/null || \
        ls /usr/lib/go-*/bin/go 2>/dev/null | head -1 || \
        echo go)
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
	@# Derleme ciktilari root'a ait kalirsa kullanicinin deposu
	@# silinemez: "rm -rf axlinux" -> "Permission denied". Ayni
	@# sorun .build/ icin de vardi, ikisi de burada duzeltiliyor.
	@OWNER="$$(stat -c %U . 2>/dev/null)"; \
	if [ -n "$$OWNER" ] && [ "$$OWNER" != "root" ]; then \
	    chown "$$OWNER" $(GO_DAEMON)/axdaemon $(GO_LOG)/axlog \
	          $(BPF_DIR)/axbpf.o 2>/dev/null || true; \
	fi

# --- Python ---
python:
	@echo "== Python =="
	@# Bytecode KAYNAK AGACINA YAZILMAZ. Once burada dogrudan
	@# "compileall $(PY_DIR)/axctl" vardi ve kullanici "sudo make
	@# install" dediginde derleyici kullanicinin deposuna root'a
	@# ait __pycache__ birakiyordu. Sonrasi: kullanici artik
	@# "rm -rf axlinux" bile yapamiyor ("Permission denied") ve
	@# senkronizasyon sessizce ESKI kaynakla surer. (Debian 12'de
	@# tam olarak goruldu: duzeltmeyi test etmek mumkun olmadi.)
	@# pycache_prefix sayesinde bytecode .build/ altina gider.
	@mkdir -p .build/pycache
	@PYTHONPYCACHEPREFIX=$(CURDIR)/.build/pycache \
		$(PYTHON) -m compileall -q $(PY_DIR)/axctl
	@# Calisma zamani bagimliliklari. Onceki surumde hic kontrol
	@# yoktu; Ubuntu'da click/rich/yaml baska paketler sayesinde
	@# zaten kurulu oldugu icin sorun gorunmedi, Debian'da
	@# "ModuleNotFoundError: No module named 'click'" ile CLI
	@# coktu ve kurulum calisan bir sistem kurdugu halde
	@# "axctl calismiyor" dedi.
	@missing=; for m in click rich yaml; do \
		$(PYTHON) -c "import $$m" >/dev/null 2>&1 || missing="$$missing $$m"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "HATA: eksik Python bagimliliklari:$$missing"; \
		echo "      kurmak icin: pip3 install -r $(PY_DIR)/requirements.txt"; \
		exit 1; \
	fi
	@echo "   bagimliliklar: click, rich, yaml"
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
test: fmt-check test-go test-static test-protection test-silent test-python

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
# Test dosyalari OTOMATIK toplanir. Once dosya adlari elle
# yaziliyordu; tests/test_version.py eklenince listede unutuldu ve
# "make test" 5 test eksik calisti. Yeni dosya ekleyen kisi
# listeyi gormedigi icin sessizce kapsam daraliyordu.
#
# unittest.TestCase iceren dosyalar: test_*.py, ancak
# test_protection.py ve test_contracts_static.py main() tasiyan
# betiklerdir (pytest onlari 0 test olarak toplar) ve OZEL
# HEDEFLERDE calistirilirlar. Bu yuzden onlar disarida birakilir.
PYTEST_FILES = $(filter-out tests/test_protection.py \
                   tests/test_contracts_static.py, \
                   $(wildcard tests/test_*.py))

test-python:
	@echo "== Python testleri =="
	@$(PYTHON) -m pytest $(PYTEST_FILES) -q \
		|| $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

# Gercek daemon + gercek enforcement. Unit test'te CALISMAZ:
# calisan bir axdaemon ve yuklu bir politika gerektirir.
test-integration:
	@echo "== Entegrasyon (calisan daemon gerekli) =="
	@$(PYTHON) tests/integration.py

# --- Paketleme ---
#
# Once tek dagitim yolu kaynak + install.sh idi. Bu gercek bir
# dagitim degil: kullanici "kuruldu mu" diye soramaz, paket
# yoneticisi guncellemez, geri yuklemez.
#
# Paket DERLENMIS ikilileri icerir; hedef makinede clang/Go
# gerektirmez. Kurulum saniyeler icinde biter ve dpkg/apt ile
# yonetilir.
#
# Politika (~/.axlinux) ve audit (/var/log/axlinux) PAKETE
# girmez ve postrm'de de silinmez: kullanici verisidir.
VERSION  := $(shell sed -n 's/^const Version = "\(.*\)"$$/\1/p' \
              src/go/axdaemon/main.go)
PKGNAME  := axlinux
PKGARCH  := amd64
STAGE    := $(CURDIR)/.pkg
PKGFILE  := $(CURDIR)/../$(PKGNAME)_$(VERSION)_$(PKGARCH).deb

# --- RPM (Fedora / RHEL / openSUSE) ---
SELINUX_DIR = packaging/fedora

rpm: all
	@echo "== RPM: SELinux modulu =="
	@$(MAKE) -C $(SELINUX_DIR) 2>/dev/null \
	    || { echo "HATA: SELinux modulu derlenemedi."; \
	         echo "  selinux-policy-devel kurulu degil mi?"; exit 1; }
	@echo "== RPM: paket =="
	@rm -rf .rpmbuild
	@mkdir -p .rpmbuild/SOURCES
	@# Kaynak arsivi: uretim dosyalarini da icermeli (spec
	@# icinde make build cagriliyor)
	@tar --exclude='.git' --exclude='__pycache__' \
	    --exclude='.build' --exclude='.rpmbuild' \
	    --exclude='*.pyc' --exclude='.rpm' \
	    -czf .rpmbuild/SOURCES/axlinux-$(VERSION).tar.gz 	    --transform 's,^,axlinux-$(VERSION)/,' .
	@rpmbuild --define "_topdir $(CURDIR)/.rpmbuild" \
	    --define "_sourcedir $(CURDIR)/.rpmbuild/SOURCES" \
	    --define "_build_id_links none" \
	    -bb $(SELINUX_DIR)/axlinux.spec 2>&1 | tail -20
	@RPM=$$(ls -t $(CURDIR)/.rpmbuild/RPMS/*/axlinux-*.rpm 2>/dev/null | head -1); \
	 if [ -z "$$RPM" ]; then echo "HATA: RPM uretilemedi"; exit 1; fi; \
	 cp "$$RPM" $(CURDIR)/../axlinux-$(VERSION)-1.x86_64.rpm; \
	 echo "  uretildi: $(CURDIR)/../axlinux-$(VERSION)-1.x86_64.rpm"; \
	 rpm -qip "$$RPM" | sed 's/^/  /'

rpm-install: rpm
	@echo "  kurulum: sudo dnf install -y ../axlinux-$(VERSION)-1.x86_64.rpm"

.PHONY: rpm rpm-install

package: all
	@echo "== Paketleme: $(PKGNAME) $(VERSION) =="
	@rm -rf $(STAGE)
	@install -d $(STAGE)/DEBIAN
	@# dpkg-deb ikili paket icin "Package:" alaninin basta olmasini
	@# istiyor; kaynak kontrolu (Source:) ile ikili kontrol
	@# (Package:) ayri dosyada tutulur.
	@sed "s/^Version: .*/Version: $(VERSION)/" packaging/debian/control.bin \
	    > $(STAGE)/DEBIAN/control
	@install -m 0755 packaging/debian/postinst  $(STAGE)/DEBIAN/postinst
	@install -m 0755 packaging/debian/prerm     $(STAGE)/DEBIAN/prerm
	@install -m 0755 packaging/debian/postrm    $(STAGE)/DEBIAN/postrm
	@# Uygulama
	@install -d $(STAGE)/usr/local/bin $(STAGE)/usr/lib/axlinux
	@install -m 0755 $(GO_DAEMON)/axdaemon $(STAGE)/usr/local/bin/axdaemon
	@install -m 0755 $(GO_LOG)/axlog       $(STAGE)/usr/local/bin/axlog
	@install -m 0755 $(BPF_DIR)/axbpf.o    $(STAGE)/usr/lib/axlinux/axbpf.o
	@# Python paketi AXCTL/ ALT DIZININE kurulur; "make install"
	@# ile ayni duzen. Once duz kuruluyordu (/usr/lib/axlinux/cli.py)
	@# ve kod "axctl.cli" bekledigi icin paket ESKI kurulumu
	@# (".../axctl/") ice aliyordu; sonuc yeni surum degil eski
	@# surum calisiyordu. Sadece gercek kurulumla yakalandi:
	@#   axctl version -> "No such command 'version'"
	@install -d $(STAGE)/usr/lib/axlinux/axctl
	@install -m 0644 $(PY_DIR)/axctl/*.py  $(STAGE)/usr/lib/axlinux/axctl/
	@install -m 0644 $(PY_DIR)/requirements.txt $(STAGE)/usr/lib/axlinux/axctl/
	@install -m 0644 $(PY_DIR)/pyproject.toml $(STAGE)/usr/lib/axlinux/axctl/
	@# CLI giris noktasi: paket dizininden yukler
	@install -m 0755 packaging/axctl $(STAGE)/usr/local/bin/axctl
	@# Servisler ve tmpfiles
	@install -d $(STAGE)/lib/systemd/system $(STAGE)/usr/lib/tmpfiles.d
	@install -m 0644 packaging/axdaemon.service \
	    $(STAGE)/lib/systemd/system/axdaemon.service
	@install -m 0644 packaging/axlog.service \
	    $(STAGE)/lib/systemd/system/axlog.service
	@install -m 0644 packaging/axlinux-tmpfiles.conf \
	    $(STAGE)/usr/lib/tmpfiles.d/axlinux.conf
	@# Ornek politikalar
	@install -d $(STAGE)/etc/axlinux
	@for f in examples/*.yaml; do install -m 0644 $$f $(STAGE)/etc/axlinux/; done
	@# Belgeler
	@install -d $(STAGE)/usr/share/doc/$(PKGNAME)
	@install -m 0644 DAGITIM.md README.md CHANGELOG.md \
	    $(STAGE)/usr/share/doc/$(PKGNAME)/
	@install -d $(STAGE)/usr/share/doc/$(PKGNAME)/docs
	@install -m 0644 docs/*.md $(STAGE)/usr/share/doc/$(PKGNAME)/docs/
	@# Installed-Size TUM dosyalar yerlestikten sonra hesaplanir.
	@# Once placeholder vardi ve staging daha bitmeden
	@# hesaplaniyordu; sonuc bos deger.
	@# Tek recipe satiri: make her satiri AYRI bir shell'de
	@# calistirir, $SIZE sonraki satira tasinmaz ve deger bos
	@# kalir ("Installed-Size: " olarak yaziliyordu).
	@SIZE="$$(du -ks $(STAGE) | cut -f1)"; \
	 sed -i "s/^Installed-Size: .*/Installed-Size: $$SIZE/" \
	    $(STAGE)/DEBIAN/control; \
	 grep -q "^Installed-Size: [0-9]" $(STAGE)/DEBIAN/control || \
	    { echo "HATA: Installed-Size hesaplanamadi (SIZE='$$SIZE')"; \
	      exit 1; }
	@dpkg-deb --root-owner-group --build $(STAGE) $(PKGFILE) >/dev/null
	@rm -rf $(STAGE)
	@echo "  uretildi: $(PKGFILE)"
	@dpkg-deb --info $(PKGFILE) | sed 's/^/  /'
	@echo "  kurulum:  sudo dpkg -i $(PKGFILE)"
	@echo "  kaldirma: sudo apt remove axlinux   (politika ve audit korunur)"

# --- Lint ---
# gofmt denetimi CI'a da eklenebilsin diye ayri hedef.
# Once 13 dosya bicimsizdi ve kimse fark etmedi; bicim tutarliligi
# bir teslim kriteridir, tavsiye degil.
fmt-check:
	@# IKI modul var: axdaemon VE axlog. Once yalnizca axdaemon
	@# kontrol ediliyordu; axlog'daki bicim ihlalleri sessizce
	@# geciyordu (4 dosya). Iki modulun toplami kontrol ediliyor.
	@# Her modul icin AYRI alt kabuk: tek kabukta ikinci
	@# "cd $(GO_LOG)" goreli yoldan calisiyor ve ilk cd'den
	@# sonra hedef bulunamiyor ("No such file or directory").
	@out=$$( (cd $(GO_DAEMON) && gofmt -l .) ; \
	        (cd $(GO_LOG)    && gofmt -l .) ); \
	if [ -n "$$out" ]; then \
		echo "HATA: gofmt'a uymayan dosyalar:"; echo "$$out"; exit 1; \
	fi
	@echo "gofmt: tum dosyalar temiz"

lint:
	@cd $(GO_DAEMON) && $(GO) vet ./...
	@cd $(GO_LOG)    && $(GO) vet ./...

fmt:
	@cd $(GO_DAEMON) && $(GO) fmt ./...
	@cd $(GO_LOG)    && $(GO) fmt ./...

# --- Kurulum ---
install: all
	@echo "== Kurulum =="
	@# Derleme ciktilarinin sahibi duzeltilir.
	@#
	@# "sudo make install" derleme adimlarini root olarak calistirir
	@# ve .build/ altina root'a ait bytecode birakir. Sonrasi
	@# kullanicinin DEPOSU silinemez:
	@#   rm -rf axlinux -> "Permission denied" (60+ dosya)
	@# Yeni kaynak aktarimi sessizce gerceklesmez ve testler
	@# GUNCEL OLMAYAN kodun sonucunu verir. Ubuntu ve Pardus'ta
	@# yasandi.
	@#
	@# Bu duzeltme install.sh icinde de var; burada TEKRAR
	@# edilmesinin nedeni iki ayri giris noktasi olmasi:
	@# docs/INSTALL.md "sudo make install" oneriyor. Yalnizca
	@# install.sh'de duzeltilseydi o yoldan kurulum yapan
	@# kullanici ayni hatayi yasardi.
	@if [ -d .build ]; then \
	    OWNER="$$(stat -c %U . 2>/dev/null)"; \
	    if [ -n "$$OWNER" ] && [ "$$OWNER" != "root" ]; then \
	        chown -R "$$OWNER" .build 2>/dev/null || true; \
	    fi; \
	fi
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
	@install -m 0644 $(PY_DIR)/requirements.txt $(PY_DIR)/pyproject.toml $(LIBDIR)/axctl/
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
	@# /run/axlinux'i tmpfiles yonetir; hicbir servis sahiplenmez
	@# (bkz. axlinux-tmpfiles.conf icindeki kanit).
	@install -m 0644 packaging/axlinux-tmpfiles.conf \
		$(DESTDIR)/usr/lib/tmpfiles.d/axlinux.conf 2>/dev/null || true
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
	@rm -f $(DESTDIR)/usr/lib/tmpfiles.d/axlinux.conf
	@rm -rf $(DESTDIR)/usr/share/doc/axlinux
	@echo "   kaldirildi"

clean:
	@$(MAKE) -C $(BPF_DIR) clean
	@rm -f $(GO_DAEMON)/axdaemon $(GO_LOG)/axlog
	@find $(PY_DIR) -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "   temizlendi"
