# AXlinux eBPF LSM programlari
#
# Tum kancalar tek bir nesnede (axbpf.o) derlenir: map'lerin tek
# kopyasi olur ve cilium/ebpf tek seferde yukleyebilir.
#
# vmlinux.h kernel BTF'sinden uretilir. Elle struct yazilmaz.

CLANG   ?= clang
BPFTOOL ?= bpftool
OBJDUMP  ?= llvm-objdump
ARCH    ?= x86

BTF     := /sys/kernel/btf/vmlinux
VMLINUX := vmlinux.h
BUNDLE  := axbpf.o

# Program bolumleri tek tek derlenip sonra birlestirilmez; hepsi
# axbpf.c icinden tek komutla derlenir.
CFLAGS := -target bpf \
          -O2 -g -Wall \
          -Wno-unused-value \
          -Wno-pointer-sign \
          -Wno-compare-distinct-pointer-types \
          -Wno-unused-function \
          -D__TARGET_ARCH_$(ARCH) \
          -I.

HOOKS := hooks_file_open.inc \
         hooks_inode_permission.inc \
         hooks_bprm_check_security.inc \
         hooks_socket_connect.inc \
         hooks_socket_bind.inc

.PHONY: all clean vmlinux check-env verify

all: check-env vmlinux $(BUNDLE)

check-env:
	@command -v $(CLANG) >/dev/null || { echo "HATA: clang bulunamadi"; exit 1; }
	@test -r $(BTF) || { echo "HATA: $(BTF) okunamadi (kernel BTF gerekli)"; exit 1; }

vmlinux: $(VMLINUX)

# vmlinux.h bir DERLEME ARTIKLIDIR; depoda tutulmaz.
#
# Elle uretilmis bir dosya kullanilacaksa once `make vmlinux` calistirilir.
# `make` bunu otomatik olarak dogru yapar: dosya hedef disi bir
# cekirdekte uretilmisse yeniden uretilir.
$(VMLINUX):
	@echo ">> vmlinux.h uretiliyor (kernel BTF)..."
	@$(BPFTOOL) btf dump file $(BTF) format c > $@.tmp
	@mv $@.tmp $@
	@echo ">> vmlinux.h hazir: $$(wc -l < $@) satir"

$(BUNDLE): axbpf.c axbpf.h $(VMLINUX) $(HOOKS)
	$(CLANG) $(CFLAGS) -c $< -o $@

# Derleme sonrasi dogrulama.
#
# Bolum adlarinin var olmasi YETMEZ: bir program derlenmis ama
# govdesi bos (optimizer elenmis) olabilir ya da beklenen map
# referanslari hic kalmamis olabilir. Boylece "5/5 kanca bagli"
# gorunurken hicbir sey engellenmiyor olur.
#
# ONEMLI: nesne uzerinde sembol adi aramak yanlis bir denetim
# yontemidir. ax_fill_path, ax_protected ve ax_set_port
# __always_inline tanimlidir; -O2'de gomulurler ve nesnede
# sembol olarak gorunmezler. Bu yuzden dogrulama RELOCATION
# uzerinden yapilir: her kancanin bytecode'i hangi map'lere
# bagli? (bkz. asagida "kanca -> map baglantisi")
#
# readelf bolum adlarini kirpar; llvm-objdump daha guvenilir.
verify: $(BUNDLE)
	@echo ">> dogrulaniyor..."
	@# Bolum adi 2. alanda TAM olarak "lsm/<ad>" olmali. Serbest
	@# metin denetimi ".rellsm/file_open" satirini da eslestirir
	@# (cünkü "rel" + "lsm/file_open") ve 5 yerine 10 sayar.
	@for s in file_open inode_permission bprm_check_security socket_connect socket_bind; do \
		$(OBJDUMP) -h $(BUNDLE) 2>/dev/null | awk -v s="lsm/$$s" \
			'$$2 == s { found = 1 } END { exit(found ? 0 : 1) }' \
			|| { echo "HATA: $$s bolumu yok"; exit 1; }; \
		echo "   ok: lsm/$$s"; \
	done
	@$(OBJDUMP) -h $(BUNDLE) 2>/dev/null | awk '$$2 == ".maps" { found = 1 } END { exit(found ? 0 : 1) }' \
		|| { echo "HATA: .maps bolumu yok"; exit 1; }
	@echo "   ok: .maps"
	@readelf -h $(BUNDLE) | grep -q "Linux BPF" \
		|| { echo "HATA: ELF makinesi BPF degil"; exit 1; }
	@echo "   ok: ELF = Linux BPF"

	@echo ">> kanca -> map baglantisi dogrulaniyor..."
	@# Gerekce yukarida (make yorumu). Kisa olarak: sembol denetimi
	@# yanlistir cunku yardimcilar __always_inline olduklari icin
	@# gomulur ve nesnede gorunmez. Dogru kanit relocation verisidir:
	@# bir kanca bu 6 map icinden birine bagli degilse, o kanca
	@# hicbir sey yapmiyor demektir.
	@# KANCA BASINA SOZLESME. Her kancanin ihtiyaci olan map'ler
	@# farklidir ve bu bir tesaduf degil, kasitli bir tasarimdir:
	@#
	@#   lsm/bprm_check_security  -> allow_map YOK. exec kancası
	@#     deny-only calisir: yalnizca EFFECT_DENY engellenir.
	@#     Bir izin listesi (allowlist) exec icin guvenlik acidan
	@#     yanlistir: beyaz listeye giren her sey calisir, listeye
	@#     girmeyen hicbir sey calismaz. Bu yuzden allow_map'e
	@#     bakilmaz. Bu kuralin karsi tarafi, "effect: allow"
	@#     yazan file.execute kurallarinin sessizce islememesi
	@#     demektir; bu yuzden policy dogrulayici bu kombinasyonu
	@#     acik hata ile reddetmelidir.
	@#
	@#   diger dort kanca -> 6 map'in tamami (yol cozulur, once
	@#     deny sonra allow sorgulanir, karar audit'e yazilir).
	@#
	@# Yeni kanca eklerken REQ listesini de guncelle.
	@$(OBJDUMP) -r $(BUNDLE) 2>/dev/null | awk ' \
	function req(s) { \
		if (s == "lsm/bprm_check_security") \
			return "mode_map key_scratch deny_map audit_buffer event_scratch"; \
		return "mode_map key_scratch allow_map deny_map audit_buffer event_scratch"; \
	} \
	function flush(   n, a, i, miss) { \
		if (sec !~ /^lsm\//) return; \
		n = split(req(sec), a, " "); miss = ""; \
		for (i = 1; i <= n; i++) if (!(a[i] in seen)) miss = miss " " a[i]; \
		if (miss != "") { printf "   HATA: %s eksik map referansi:%s\n", sec, miss; bad = 1 } \
		else printf "   ok: %s -> %d map bagli\n", sec, n; \
	} \
	/^RELOCATION RECORDS FOR/ { flush(); sec = $$4; gsub(/[\[\]:]/, "", sec); delete seen; next } \
	{ for (i = 1; i <= NF; i++) if ($$i ~ /^(mode_map|key_scratch|allow_map|deny_map|audit_buffer|event_scratch)$$/) seen[$$i] = 1 } \
	END { flush(); if (bad) exit 1 } \
	' || { echo "HATA: kanca -> map baglantisi eksik"; exit 1; }

	@echo ">> bpf_d_path kullanimi denetleniyor..."
	@# bpf_d_path kullanilirsa yol alani iki konuma birden yazilir
	@# ve TUM yol kurallari sessizce tutmaz. Sekme ve sembol
	@# ciktilarinin ikisi de taranir.
	@if { $(OBJDUMP) -t $(BUNDLE) 2>/dev/null; $(OBJDUMP) -d $(BUNDLE) 2>/dev/null; } \
		| grep -q "bpf_d_path"; then \
		echo "HATA: bpf_d_path cagrisi var; bloklu cozumleyici kullanilmiyor"; \
		exit 1; \
	fi
	@echo "   ok: bpf_d_path yok (bloklu cozumleyici)"

	@echo ">> policy map tanimlari denetleniyor..."
	@for m in allow_map deny_map mode_map; do \
		$(OBJDUMP) -t $(BUNDLE) 2>/dev/null | grep -q "$$m" \
			|| { echo "HATA: $$m tanimi yok"; exit 1; }; \
	done
	@echo "   ok: allow_map, deny_map, mode_map"

	@echo ">> program sayisi denetleniyor..."
	@np=$$($(OBJDUMP) -h $(BUNDLE) 2>/dev/null | awk '$$2 ~ /^lsm\// { print $$2 }' | sort -u | wc -l); \
		echo "   lsm bolumu sayisi: $$np"; \
		test "$$np" -eq 5 \
			|| { echo "HATA: 5 lsm bolumu bekleniyordu, $$np bulundu"; exit 1; }
	@echo "   ok: 5 lsm programi"
	@echo ">> dogrulama basarili"

clean:
	rm -f $(BUNDLE) *.bpf.o *.tmp
