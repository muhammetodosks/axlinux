/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - tek eBPF LSM nesnesi
 *
 * Tum LSM kancalari ve map'ler TEK bir ELF icinde bulunur. Boylece
 * map'lerin yalnizca bir kopyasi olur ve cilium/ebpf tek
 * LoadCollectionObject cagrisiyla hem programlari hem map'leri alir.
 *
 * Kancalar kendi dosyalarinda .inc olarak tutulur ve buraya include
 * edilir. Yeni kanca eklemek icin SIRAYLA:
 *   1) hooks_<isim>.inc yaz (BPF_PROG ile)
 *   2) buraya #include ekle
 *   3) src/bpf/Makefile icindeki HOOKS listesine ekle
 *      (aksi halde make, .inc degistiginde yeniden derlemez)
 *   4) Go tarafindaki internal/lsm/lsm.go HookTable'a ekle
 *      (aksi halde program yuklenir ama baglanmaz)
 * Bu dort adim atlindiginda ya program derlenmez ya da baglanmaz;
 * her iki durumda da enforcement sessizce eksik kalir.
 */
#include "axbpf.h"

char _license[] SEC("license") = "GPL";

/* Kanca uygulamaları */
#include "hooks_file_open.inc"
#include "hooks_inode_permission.inc"
#include "hooks_bprm_check_security.inc"
#include "hooks_socket_connect.inc"
#include "hooks_socket_bind.inc"
