# AXlinux SELinux politika modulunu derler.
#
# Fedora SELinux'u ENFORCING olarak gelir ve AXlinux'i kendi
# alaninda (axlinux_daemon_t) calistirmak icin bu modul
# gereklidir. Modul kurulmadan once axdaemon
# unconfined_service_t'de calisir; SELinux onu KISITLAMAZ ve
# Fedora'nin sertlastirilmis profilinde (unconfined devre disi)
# AXlinux CALISMAZ.
#
# DERS: onceki surumde bu Makefile "eski .pp"yi kullanma riski
# tasiyordu:
#   make clean -> .pp silinmedi
#   make       -> "Compiling" ciktisi GELMEDI
#   axlinux.pp -> degismedi, ayni eski dosya
#   semodule -i -> eski modul "KURULDU" gibi gorunuyordu
# yani bir politika hatasi fark edildi ama eski politika sessizce
# kurulmaya devam etti. Artik her seferinde sifirdan uretilir.

SEMODULE  = axlinux

SELINUX_DEVEL_MAKEFILE = /usr/share/selinux/devel/Makefile

# .if DERLEME SIRASINA GIRMEZ.
# Once "SEMODULE_OBJS = axlinux.if axlinux.te" idi; .if once
# birlesince checkmodule "no module specification found" dedi ve
# hicbir modul derlenmedi. .if yalnizca arayuz olarak kurulur.
SEMODULE_OBJS = $(SEMODULE).te

all: $(SEMODULE).pp

$(SELINUX_DEVEL_MAKEFILE):
	@echo "HATA: $$(SELINUX_DEVEL_MAKEFILE) yok."
	@echo "  sudo dnf install selinux-policy-devel"
	@exit 1

# Her zaman sifirdan: -B (unconditional) ve onceki cikti silinir.
$(SEMODULE).pp: $(SEMODULE_OBJS) | $(SELINUX_DEVEL_MAKEFILE)
	@echo "  SELinux modulu derleniyor: $(SEMODULE).pp"
	@rm -f $@ tmp/$(SEMODULE).mod tmp/$(SEMODULE).tmp
	$(MAKE) -B -f $(SELINUX_DEVEL_MAKEFILE) SEMODULE=$(SEMODULE) $@
	@test -f $@ || { echo "HATA: $@ uretilmedi"; exit 1; }
	@echo "  uretildi: $@ ($$(stat -c%s $@) bayt)"

check:
	$(MAKE) -f $(SELINUX_DEVEL_MAKEFILE) check

clean:
	-@$(MAKE) -f $(SELINUX_DEVEL_MAKEFILE) clean 2>/dev/null
	@rm -f *.pp *.mod tmp/*.tmp
	@echo "  temizlendi"

# Politika + arayuz dosyalarini kurar.
install: $(SEMODULE).pp
	install -m 0644 $(SEMODULE).pp $(DESTDIR)%(datadir)/selinux/packages/
	install -m 0644 $(SEMODULE).if \
	    $(DESTDIR)%(datadir)/selinux/devel/include/ 2>/dev/null || :

.PHONY: all check clean install
