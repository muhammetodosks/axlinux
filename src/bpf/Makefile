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

$(VMLINUX):
	@echo ">> vmlinux.h uretiliyor (kernel BTF)..."
	@$(BPFTOOL) btf dump file $(BTF) format c > $@.tmp
	@mv $@.tmp $@
	@echo ">> vmlinux.h hazir: $$(wc -l < $@) satir"

$(BUNDLE): axbpf.c axbpf.h $(VMLINUX) $(HOOKS)
	$(CLANG) $(CFLAGS) -c $< -o $@

# Derleme sonrasi dogrulama: her kanca bolumu ve map'ler yerinde mi.
# readelf bolum adlarini kirpar; llvm-objdump guvenilir.
verify: $(BUNDLE)
	@echo ">> dogrulanıyor..."
	@for s in file_open inode_permission bprm_check_security socket_connect socket_bind; do \
		$(OBJDUMP) -h $(BUNDLE) 2>/dev/null | grep -qE "lsm/$$s[[:space:]]" \
			|| { echo "HATA: lsm/$$s bolumu yok"; exit 1; }; \
		echo "   ok: lsm/$$s"; \
	done
	@$(OBJDUMP) -h $(BUNDLE) 2>/dev/null | grep -qE "\.maps[[:space:]]" \
		|| { echo "HATA: .maps bolumu yok"; exit 1; }
	@echo "   ok: .maps"
	@readelf -h $(BUNDLE) | grep -q "Linux BPF" \
		|| { echo "HATA: ELF makinesi BPF degil"; exit 1; }
	@echo "   ok: ELF = Linux BPF"
	@echo ">> dogrulama basarili"

clean:
	rm -f $(BUNDLE) *.bpf.o *.tmp
