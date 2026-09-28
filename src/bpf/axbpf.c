/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - tek eBPF LSM nesnesi
 *
 * Tum LSM kancalari ve map'ler TEK bir ELF icinde bulunur. Boylece
 * map'lerin yalnizca bir kopyasi olur ve cilium/ebpf tek
 * LoadCollectionObject cagrisiyla hem programlari hem map'leri alir.
 *
 * Kancalar kendi dosyalarinda .inc olarak tutulur ve buraya include
 * edilir. Yeni kanca eklemek icin: hooks_<isim>.inc yaz, sonra buraya
 * include ekle ve PROGS listesine ismi ekle.
 */
#include "axbpf.h"

char _license[] SEC("license") = "GPL";

/* Kanca uygulamaları */
#include "hooks_file_open.inc"
#include "hooks_inode_permission.inc"
#include "hooks_bprm_check_security.inc"
#include "hooks_socket_connect.inc"
#include "hooks_socket_bind.inc"
