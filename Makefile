# AXlinux - ust duzey Makefile
#
# Hedefler:
#   make          -> bpf + go + python derle
#   make test     -> tum testler
#   make verify   -> sozlesme ve bolum dogrulamasi
#   make install  -> sistem dizinlerine kur

SHELL     := /bin/bash
# Kanonik on ek /usr. RPM, .deb ve kaynak kurulumu AYNI yollari
# kullanmali; aksi halde systemd birimleri yanlis yolu gosterir
# ve servis 203/EXEC ile olur.
PREFIX    ?= /usr
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

.PHONY: all bpf go python python-compile python-compile test test-go test-python test-contract \
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
	@cd $(GO_DAEMON) && $(GO) build -ldflags "-X main.Version=$(VERSION)" -o axdaemon .
	@cd $(GO_LOG)    && $(GO) build -ldflags "-X main.Version=$(VERSION)" -o axlog .
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
python: python-compile
	@echo "== Python =="
	@# Bytecode derleme python-compile hedefinde; orada.
	@# pycache_prefix sayesinde bytecode .build/ altina gider,
	@# kaynak agacina degil (root'a ait __pycache__ sorunu).
	@# Calisma zamani bagimliliklari. Onceki surumde hic kontrol
	@# yoktu; Ubuntu'da click/rich/yaml baska paketler sayesinde
	@# zaten kurulu oldugu icin sorun gorunmedi, Debian'da
	@# "ModuleNotFoundError: No module named 'click'" ile CLI
	@# coktu ve kurulum calisan bir sistem kurdugu halde
	@# "axctl calismiyor" dedi.
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
  # Sürüm TEK kaynaktan okunur: packaging/fedora/axlinux.spec.
  #
  # Önceden burada `const Version = "..."` ifadesi axdaemon/main.go
  # dosyasından kazınıyordu. Bu iki şekilde bozuluyordu:
  #   1) axlog/main.go'da surum SABIT "1.0.0" idi; RPM 1.1.0
  #      derlenirken log servisi kendini 1.0.0 olarak raporluyordu.
  #   2) axdaemon'da surum tanimi degisirse (ör. const -> var)
  #      kazima sessizce BOS string doner, paket "axlinux-.deb"
  #      adiyla uretilirdi.
  # Simdi deger spec'ten gelir ve -ldflags ile her iki ikiliye
  # de enjekte edilir; kaynak dosyalarda surum kopyasi kalmaz.
  VERSION  := $(shell sed -n 's/^Version:[[:space:]]*\(.*\)$$/\1/p' \
                packaging/fedora/axlinux.spec | head -1)
  PKGNAME  := axlinux
  PKGARCH  := amd64
  STAGE    := $(CURDIR)/.pkg
  PKGFILE  := $(CURDIR)/../$(PKGNAME)_$(VERSION)_$(PKGARCH).deb

# --- RPM (Fedora / RHEL / openSUSE) ---
SELINUX_DIR = packaging/fedora

# --- RPM IMZASI ---
#
# Gercek bir depoda dagitilan her paket imzali olmak ZORUNDADIR.
# Imzasiz paket dnf tarafindan uyarilir ve Fedora'nin sertlastirilmis
# politikasinda kurulum reddedilir.
#
# Anahtar repoda TUTULMAZ. Anahtar uretimi ve kullaniciya aktarimi
# gelistiricinin sorumlulugundadir; depo gizli anahtari private
# tutar ve sadece AYRI bir public key yayinlar.
#
#   make rpm-gpg-key    -> anahtari uretir (gpg --gen-key)
#   make rpm            -> anahtar varsa otomatik imzalar
#   make rpm-sign GPGKEY=... -> belirtilen anahtarla imzalar
#
# Anahtar YOKSA rpmbuild SESSIZCE imzasiz uretir ve ekrana bir
# uyari basar; hata vermez. Boylece gelistirici anahtari olmadan da
# paket uretebilir (imzasiz paket yalnizca test icin gecerlidir).
GPGKEY ?= $(HOME)/.gnupg/axlinux-signing-key
GPG_NAME := AXlinux Packaging
GPG_EMAIL := packaging@axlinux.invalid
# CI paketleme matrisinde SKIP_SIGN=1 kullanilir: derleme dogrulanir,
# imza dogrulanmaz. Imza gercekten VM'de (anahtarli ortamda) test edilir.
SKIP_SIGN ?= 0

# Anahtar gercekten var mi? (sadece public yeterli imzalamaya)
GPG_AVAILABLE := $(shell gpg --list-secret-keys --keyid-format=long 2>/dev/null | grep -q . && echo yes || echo no)

# _gpg_name bir ANAHTAR SECICI alir: e-posta, kullanici adi veya
# parmak izi. Dosya YOLU degil.
#
# Ilk denemede _gpg_name $(GPGKEY) verilmisti; $(GPGKEY) bir yol
# (/home/ax/.gnupg/axlinux-signing-key). rpmbuild bunu anahtar
# olarak cozemedigi icin paket IMZASIZ uretildi:
#   Header SHA256 digest: OK
#   Payload SHA256 digest: OK
#   (Signature satiri YOK)
# rpm -Kv ciktisinda digest'ler gecerli ama imza satiri hic yok;
# yani paket dogrulanmis DEGIL, sadece icerigi tutarli.
ifeq ($(GPG_AVAILABLE),yes)
RPMBUILD_GPG := --define "_gpg_name $(GPG_EMAIL)"
else
RPMBUILD_GPG :=
endif

# --- RPM imza anahtari ---
#
# GPG anahtari uretir. Idempotent DEGILDIR: anahtar zaten varsa
# dokunulmaz (yeniden uretmek eski imzalari koparirdi).
# --- journald ust siniri ---
#
# journald varsayilani kotu dosya sisteminin %10'u (en fazla 4G).
# 20 GB'lik bir Workstation kurulumunda 2 GB. AXlinux'in kendi
# audit logu sinirli olsa bile isletim sistemi gunlugu sinirsiz
# kalirsa o sinir anlamsizlasir.
#
# Ana journald.conf DEGISTIRILMEZ; standart drop-in dizini
# kullanilir (systemd oncelik sirasi: drop-in > ana dosya).
# Yonetici dosyayi silerek ayari geri alabilir.
.PHONY: journald-limit journald-show journald-revert
JOURNALD_DROPIN := /etc/systemd/journald.conf.d/10-axlinux.conf

journald-limit:
	@echo "== journald ust siniri =="
	@install -d -m 0755 /etc/systemd/journald.conf.d
	@install -m 0644 packaging/journald/10-axlinux.conf $(JOURNALD_DROPIN)
	@systemctl restart systemd-journald 2>/dev/null || true
	@systemd-analyze cat-config systemd/journald.conf 2>/dev/null | \
	    grep -E "SystemMaxUse|SystemKeepFree|MaxRetentionSec" | sed 's/^/    /'
	@echo "  kuruldu: $(JOURNALD_DROPIN)"

journald-show:
	@echo "== etkin journald ayarlari =="
	@systemd-analyze cat-config systemd/journald.conf 2>/dev/null | \
	    grep -E "^#?\s*(SystemMaxUse|SystemMaxFileSize|SystemKeepFree|MaxRetentionSec)=" | sed 's/^/  /'

journald-revert:
	@rm -f $(JOURNALD_DROPIN)
	@systemctl restart systemd-journald 2>/dev/null || true
	@echo "  geri alindi: $(JOURNALD_DROPIN)"

.PHONY: rpm-gpg-key rpm-sign rpm-verify-sign rpm-export-key rpm

rpm-gpg-key:
	@echo "== RPM imza anahtari =="
	@if gpg --list-secret-keys --keyid-format=long 2>/dev/null | grep -q .; then \
	    echo "  Secret anahtar zaten var, dokunulmuyor."; \
	else \
	    mkdir -p "$(dir $(GPGKEY))"; \
	    gpg --batch --yes --pinentry-mode loopback --passphrase "" \
	        --quick-generate-key "$(GPG_NAME) <$(GPG_EMAIL)>" rsa4096 sign never; \
	    echo "  Anahtar uretildi."; \
	fi
	@echo "  PUBLIC anahtari disari aktar (depo icin): make rpm-export-key"

rpm-export-key:
	@mkdir -p dist
	@gpg --armor --export "$(GPG_EMAIL)" > dist/axlinux-signing-key.asc
	@echo "  dist/axlinux-signing-key.asc uretildi"
	@echo "  Kullanicilar: rpm --import dist/axlinux-signing-key.asc"

# Uretilen RPM'i imzala
rpm-sign:
	@test -n "$(RPMFILE)" || { echo "HATA: RPMFILE=<yol> verin"; exit 1; }
	@rpmsign --addsign "$(RPMFILE)" --define "_gpg_name $(GPG_EMAIL)"
	@echo "  imzalandi: $(RPMFILE)"

rpm-verify-sign:
	@test -n "$(RPMFILE)" || { echo "HATA: RPMFILE=<yol> verin"; exit 1; }
	@rpm -Kv "$(RPMFILE)"

# `rpm` `all` UZERINE bagli degil.
#
# NEDEN: `all = bpf go python` ve `python` hedefi CALISMA ZAMANI
# bagimliliklarini (click/rich/yaml) kontrol edip yoksa HATA veriyor.
# Oysa RPM yalnizca .py KAYNAKLARINI paketler; bu moduller kurulum
# aninda gerekir, DERLEME aninda degil. Dogrulanmis olarak ortaya
# cikti: Fedora 43 konteynerinde gerekli tum derleme paketleri
# kuruluydu, `make rpm` yine "eksik Python bagimliliklari" ile
# basarisiz oldu.
#
# Sonuc: derleme ortami calisma zamani modullerini kurmak zorunda
# kaliyordu ve CI paketleme matrisi de ayni hataya dusuyordu.
#
# Duzeltme: rpm yalnizca bpf ve go'ya bagli. Python KAYNAKLARI
# zaten agac durumunda, derlenecek bir sey yok.
rpm: bpf go
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
	    $(RPMBUILD_GPG) \
	    -bb $(SELINUX_DIR)/axlinux.spec 2>&1 | tail -20
	@RPM=$$(ls -t $(CURDIR)/.rpmbuild/RPMS/*/axlinux-*.rpm 2>/dev/null | head -1); \
	 if [ -z "$$RPM" ]; then echo "HATA: RPM uretilemedi"; exit 1; fi; \
	 cp "$$RPM" $(CURDIR)/../axlinux-$(VERSION)-1.x86_64.rpm; \
	 echo "  uretildi: $(CURDIR)/../axlinux-$(VERSION)-1.x86_64.rpm"; \
	 rpm -qip "$$RPM" | sed 's/^/  /'

	@echo "== RPM: imzali =="
	@OUT=$(CURDIR)/../axlinux-$(VERSION)-1.x86_64.rpm; \
	 if [ "$(SKIP_SIGN)" = "1" ]; then \
	    echo "  SKIP_SIGN=1: imzalamadan geciliyor (CI matrisi)"; \
	    echo "  bu paket DAGITILMAZ; yalnizca derleme dogrulanir"; \
	    echo "  uretildi: $$OUT"; exit 0; \
	 fi; \
	 if gpg --list-secret-keys "$(GPG_EMAIL)" >/dev/null 2>&1; then \
	    rpmsign --addsign "$$OUT" --define "_gpg_name $(GPG_EMAIL)" \
	        && echo "  imzalandi: $$OUT"; \
	 else \
	    echo "HATA: GPG anahtari yok ($(GPG_EMAIL))."; \
	    echo "  Imzasiz RPM gercek depoda DAGITILAMAZ."; \
	    echo "  Once 'make rpm-gpg-key' calistirin."; \
	    rm -f "$$OUT"; \
	    exit 1; \
	 fi; \
	 rpm -Kv "$$OUT" | grep -q "signature.*OK" \
	    || { echo "HATA: imza dogrulanamadi"; rm -f "$$OUT"; exit 1; }; \
	 echo "  imza dogrulandi: $$OUT"; \
	 rpm -Kv "$$OUT" | grep signature | sed "s/^/    /"

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
	@install -d $(STAGE)/usr/bin $(STAGE)/usr/lib/axlinux
	@install -m 0755 $(GO_DAEMON)/axdaemon $(STAGE)/usr/bin/axdaemon
	@install -m 0755 $(GO_LOG)/axlog       $(STAGE)/usr/bin/axlog
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
	@install -m 0755 packaging/axctl $(STAGE)/usr/bin/axctl
	@# Servisler ve tmpfiles
	@install -d $(STAGE)/lib/systemd/system $(STAGE)/usr/lib/tmpfiles.d
	@install -m 0644 packaging/axdaemon.service \
	    $(STAGE)/lib/systemd/system/axdaemon.service
	@install -m 0644 packaging/axlog.service \
	    $(STAGE)/lib/systemd/system/axlog.service
	@install -m 0644 packaging/axlinux-tmpfiles.conf \
	    $(STAGE)/usr/lib/tmpfiles.d/axlinux.conf
	@# journald ust siniri. RPM tarafi packaging/journald altinda
	@# drop-in olarak kuruyor; .deb tarafinda HIC KURULUMUYORDU,
	@# yani Debian/Ubuntu sistemlerinde /var/log/journal sinirsiz
	@# kaliyordu. Ayni dosya, ayni sinirlar.
	@install -d $(STAGE)/etc/systemd/journald.conf.d
	@install -m 0644 packaging/journald/10-axlinux.conf \
	    $(STAGE)/etc/systemd/journald.conf.d/10-axlinux.conf
	@# Ornek politikalar
	@install -d $(STAGE)/etc/axlinux
	@for f in examples/*.yaml; do install -m 0644 $$f $(STAGE)/etc/axlinux/; done
	# SISTEM GENELI POLITIKA DIZINI
	#
	# RPM yolu bu dizini spec'te kuruyor; .deb yolu KURMUYORDU.
	# Sonuc: dpkg ile kurulan Debian/Ubuntu sisteminde politika
	# reboot sonrasi kayboluyor ve kalici politika yazilamiyordu
	# (install.sh yolunda da ayni eksik vardi, dort kurulum yolundan
	# ucu birbirinden farkli sistem kuruyordu).
	@install -d -m 0750 $(STAGE)/etc/axlinux/policies.d
	@install -m 0644 packaging/fedora/axlinux-sample-workstation.yaml \
	    $(STAGE)/etc/axlinux/policies.d/00-sample-workstation.yaml

	# CONFFILES: politika dosyalari KULLANICI VERISIDIR.
	#
	# dpkg -r ile kaldirildiginda bu dosyalarin SILINMEMESI gerekir.
	# Gozlemlenen hata: "dpkg -r axlinux" sonrasi
	# /etc/axlinux/policies.d/00-sample-workstation.yaml kayboldu.
	# dpkg, conffiles olarak isaretlenmeyen /etc dosyalarini kaldirmada
	# SILER; RPM tarafi ayni durumda "%config(noreplace)" ile
	# KORUYOR. Iki paket yolu ayni davranmiyordu.
	@# conffiles listesini kurulumdan SONRA uret: dosya yollari
	@# $(STAGE) icinde o an mevcut olmali.
	@{ \
	  echo "/etc/axlinux/desktop.yaml"; \
	  echo "/etc/axlinux/minimal.yaml"; \
	  echo "/etc/axlinux/web-server.yaml"; \
	  echo "/etc/axlinux/policies.d/00-sample-workstation.yaml"; \
	  echo "/etc/systemd/journald.conf.d/10-axlinux.conf"; \
	} > $(STAGE)/DEBIAN/conffiles
	@chmod 0644 $(STAGE)/DEBIAN/conffiles
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
# `install` `all` UZERINE bagli; `all` python HEDEFINI de calistirir.
# python hedefi calisma zamani bagimliliklarini (click/rich/yaml)
# kontrol eder ve eksikse HATA verir.
#
# Dogrulanmis olarak ortaya cikti: Fedora 41/42/43 konteynerlerinin
# ucunde de `make rpm` %build asamasini gecti ama %install asamasinda
# "eksik Python bagimliliklari" ile basarisiz oldu.
#
# Kurulum (.py dosyalarini kopyalama) calisma zamani modullerine
# ihtiyac duymaz; bunlar hedef sistemde kurulur.
# Bytecode derleme: bagimlilik kontrolu YOK, yalnizca .py -> .pyc.
python-compile:
	@mkdir -p .build/pycache
	@PYTHONPYCACHEPREFIX=$(CURDIR)/.build/pycache \
	    $(PYTHON) -m compileall -q $(PY_DIR)/axctl

# Bytecode derleme: bagimlilik kontrolu YOK, yalnizca .py -> .pyc.
# python = python-compile + bagimlilik dogrulamasi.
# install = bpf + go + python-compile (calisma zamani modullerine
# ihtiyac duymaz; onlar hedef sistemde kurulur).
install: bpf go python-compile
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
	@# axctl: TEK dogruluk kaynagi packaging/axctl.
	@#
	@# Burada ikinci bir sarmalayici uretiliyordu ve iki yol
	@# ayriydi:
	@#   RPM          packaging/axctl  (sh + python3 -c)
	@#   make install  printf ile uretilen (python betigi)
	@#
	@# Sonuc: "hangi sarmalayici kurulu?" sorusunun cevabi
	@# kurulum yoluna bagliydi. Ayrica python3 -c yonteminde
	@# sys.argv[0] = "-c" oldugu icin click "Usage: -c [OPTIONS]"
	@# yaziyordu.
	@install -m 0755 packaging/axctl $(BINDIR)/axctl
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
