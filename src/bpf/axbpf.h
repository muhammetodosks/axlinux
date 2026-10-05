/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - ortak eBPF LSM basligi
 *
 * Yapilar vmlinux.h (BTF) uzerinden gelir. Elle struct yazilmaz.
 */
#ifndef __AXBPF_H
#define __AXBPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef EPERM
#define EPERM 1
#endif

/* Aksiyon tipleri - Go tarafi ile birebir ayni numaralandirma */
#define ACTION_FILE_READ     1
#define ACTION_FILE_WRITE    2
#define ACTION_FILE_EXEC     3
#define ACTION_FILE_DELETE   4
#define ACTION_FILE_CREATE   5
#define ACTION_NET_CONNECT   6
#define ACTION_NET_BIND      7
#define ACTION_NET_ACCEPT    8
#define ACTION_PROCESS_EXEC  9

/* LSM kanca tipleri */
#define HOOK_FILE_OPEN            1
#define HOOK_INODE_PERMISSION     2
#define HOOK_BPRM_CHECK_SECURITY  3
#define HOOK_SOCKET_CONNECT       4
#define HOOK_SOCKET_BIND          5

/* Modlar */
#define MODE_DISABLED    0
#define MODE_PERMISSIVE  1
#define MODE_ENFORCING   2

#define EFFECT_DENY      0
#define EFFECT_ALLOW     1

#define DECISION_ALLOWED 0
#define DECISION_DENIED  1

#define MAX_PATH_LEN     256

/* vmlinux.h bu degerleri enum olarak saglamaz, sayisal olarak veriyoruz */
#ifndef AF_UNIX
#define AF_UNIX  1
#endif
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

/* Yol alani SABIT bloklara bolunur. Boylece eBPF tarafinda
 * calisma aninda hesaplanan indeks kalmaz: her bilesen kendi
 * bloguna yazilir, blogun ofseti derleme zamaninda sabittir.
 * Go tarafinda birlestirilir (maps.setKeyPath, audit.JoinPath).
 * Toplam boyut degismez: 16 + 8*32 + 4 = 276.
 *
 * Bu tanimlar struct policy_key'den ONCE gelmelidir. */
#ifndef AX_PATH_DEPTH
#define AX_PATH_DEPTH 8
#endif
#ifndef AX_PATH_SLOT
#define AX_PATH_SLOT  32

#endif
/* Tek bir bilesen adi bu kadar karakteri asabilir (ext4'te 255
 * olabilir; pratikte 31 yeterli ve instruction maliyetini 8 kat
 * azaltir). */
#ifndef AX_NAME_MAX
#define AX_NAME_MAX  (AX_PATH_SLOT - 1)
#endif

/* Anahtar: comm + path + action */
struct policy_key {
	char comm[16];
	char path[AX_PATH_DEPTH][AX_PATH_SLOT];
	__u32 action;
};

/* Deger: hangi kural ve ne etki */
struct policy_value {
	__u32 rule_id;
	__u32 effect;
};

/* Audit olayi (perf buffer) */
/* yol alani policy_key ile ayni sekilde blokludur; Go tarafi
 * birlestirir. Duz kopyalanirsa bloklar arka arkaya gelir ve
 * kayit okunamaz. */
struct audit_event {
	__u64 timestamp;
	__u32 pid;
	char comm[16];
	char path[AX_PATH_DEPTH][AX_PATH_SLOT];
	__u32 action;
	__u32 effect;
	__u32 decision;
	__u32 rule_id;
	__u32 hook_type;
};

/* Izin verilen kurallar */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct policy_key);
	__type(value, struct policy_value);
} allow_map SEC(".maps");

/* Yasaklanan kurallar */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct policy_key);
	__type(value, struct policy_value);
} deny_map SEC(".maps");

  /* GORUNMEYEN MOUNT KOKLERI ("alt birim kozu")
   *
   * Anahtar: mount kokunun adi (ornegin "root"). Deger: 1.
   *
   * btrfs'te kok bir ALT BIRIM olarak baglanir ve dentry zincirine
   * gorunmez bir bilesen girer:
   *
   *   /etc/ax-t8 -> ax-t8 -> etc -> root -> /
   *
   * "root" yazilirsa yol "/root/etc/ax-t8" olur; politika ise
   * "/etc/ax-t8" yazar. Anahtarlar kesismez ve kural HIC
   * UYGULANMAZ.
   *
   * /var ve /home de ayri alt birim mount'laridir, ama mount
   * koklari GORUNUR yolun parcasidir:
   *
   *   /var/ax-t8 -> ax-t8 -> var -> /     ("var" KATI LANMALI)
   *
   * Kernel ici alanlarla (mnt_parent, mnt_mountpoint) ayirt etmek
   * mumkun degil: bu alanlar bpftool ciktisinda yok ve dentry
   * tarafi her iki durumda da birebir ayni gorunuyor.
   *
   * Dogru ve genel yol: ayrimi KULLANICI ALANINDAN almak.
   * /proc/self/mountinfo'nin 4. alani mount'un dosya sistemi
   * icindeki koku, 5. alani baglandigi yerdir:
   *
   *   mountpoint=/     root=/root   -> koz "root"  (ATLANIR)
   *   mountpoint=/var  root=/var    -> koz yok     ("var" KALIR)
   *   mountpoint=/tmp  root=/       -> koz yok
   *
   * Yani root != "/" VE root != mountpoint ise koz vardir.
   * axdaemon bu adlari mountinfo'dan okuyup haritaya yazar.
   */
  struct {
  	__uint(type, BPF_MAP_TYPE_HASH);
  	__uint(max_entries, 16);
  	__type(key, char[AX_PATH_SLOT]);
  	__type(value, __u8);
  } mount_artifact_map SEC(".maps");

/* MOUNT NOKTASI ONEKI.
 *
 * mount_artifact_map "gorunmez" bir bileseni YOLDAN SILER
 * (btrfs alt birim koku "root" gibi). Bu harita ise tam
 * tersini yapar: dentry yurusunde HIC GORUNMEYEN bir oneki
 * yola EKLER.
 *
 * Sorun: /tmp Fedora'da AYRI bir mount'tur (tmpfs):
 *
 *   /proc/self/mountinfo: root=/ mountpoint=/tmp
 *   /tmp/ax-pintest  ->  dentry zinciri: ax-pintest -> "/"
 *
 * "tmp" bir dizin girdisi DEGILDIR; bir mount baglantisidir.
 * Bu yuzden dentry yurusu "/ax-pintest" uretir, "/tmp" oneki
 * KAYBOLUR ve policy "/tmp/..." kurallari sessizce tutmaz.
 *
 * Kanit:
 *   cat /etc/ax-pintest2  -> Operation not permitted  (dogru)
 *   cat /tmp/ax-pintest   -> OK, icerik sizdi          (HATA)
 *
 * Cozum: axdaemon mountinfo'da root=="/" ve mountpoint!="/"
 * olan her mount icin (dev, ino) -> mountpoint yaziyor.
 * BPF mount kokune ulastiginda bu anahtari arar ve oneki
 * yolun ALTINA ekler.
 *
 * Anahtar (dev, ino) OLMAK ZORUNDA: tum tmpfs kokleri
 * inode 1'dir (/tmp=1, /dev/shm=1, /run=1). Ayri superblock
 * ayri st_dev verir, bu yuzden cift benzersizdir.
 */
#define AX_MP_MAX 4

struct ax_mp_key {
  /* Yalnizca superblock cihazi.
   *
   * once (dev, ino) kullaniliyordu. Inode mountinfo'da YOKTUR ve
   * istat() SELinux tarafindan reddediliyor:
   *
   *   stat /sys/fs/cgroup: permission denied
   *   stat /run/user/1000: permission denied
   *   (12 mount noktasi, hepsi EACCES)
   *
   * Yani inode ancak ya istat yetkisi vererek ya da yaklasik bir
   * varsayimla elde edilebilirdi; ikisi de yanlislik kaynagi.
   *
   * mountinfo'nun 3. alani zaten superblock cihazidir
   * ("0:39"), ve kernelde i_sb->s_dev ile ayni degerdir. Tek
   * degere gore anahtarlamak istat yetkisi gerektirmez.
   *
   * Belirsizlik: ayni superblocku iki ayri yola baglamak
   * (orn. ayni tmpfs'i /tmp ve /var/tmp'ye baglamak) tek
   * kaydi paylasir. Boyle bir baglanti pratikte yoktur ve
   * sonuc, hicbir kaydin olmamasindan cok daha iyidir. */
  __u64 dev;
};

struct ax_mp_val {
  /* "/tmp" -> slot[0]="/tmp", n=1 */
  char slot[AX_MP_MAX][AX_PATH_SLOT];
  __u32 n;
  /* onceki bloklarin toplam bayt sayisi (her bilesen len+1) */
  __u32 bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, struct ax_mp_key);
  __type(value, struct ax_mp_val);
} mount_point_map SEC(".maps");

/* Audit perf buffer */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} audit_buffer SEC(".maps");

/* Aktif mod (0=disabled, 1=permissive, 2=enforcing) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} mode_map SEC(".maps");

/* Ogrenme bayragi. Tek hucreli dizi: 0 = gozlem yok,
 * 1 = izin verilen operasyonlar da audit olayina donusur.
 *
 * Neden gerekiyor: kancalar yalnizca DENY kurali eslesen
 * operasyonlarda olay uretiyordu
 *   val = ax_lookup(key);
 *   if (!val || val->effect != EFFECT_DENY)
 *           return 0;
 * Ogrenme modunun ise tam tersi bir amaci var: "normalde ne
 * yapiyorsun" gozlemi. Normal isler tanim geregi IZIN VERILEN
 * operasyonlardir, yani hicbiri olay uretmiyordu. Sonuc:
 * ogrenme modu AÇILSA BILE sifir gozlem toplaniyordu; ozellik
 * kullaniciya "3 gun kayit tutulacak" yazip hicbir sey
 * toplanmiyordu.
 *
 * Bayrak yalnizca ogrenme acikken set edilir: her izinli
 * dosya okumasini surekli audit etmek sistemde gereksiz
 * yuk olusturur. Ogrenme acik/kapali ogrendigi icin yol
 * operatorun istegedir.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} learn_map SEC(".maps");

/* Stack limiti (512B) policy_key + audit_event toplamini asamaz.
 * Bu yuzden calisma zamani tamponlari per-CPU map icinde tutulur. */
/* iki slot: 0 = yol kurali anahtari, 1 = surec kurali anahtari.
 * bprm_check_security iki anahtari ayni anda sorgular; ikinci
 * slot sayesinde ikinci bpf_map_lookup_elem zincirine gerek
 * kalmaz ve verifier'in instruction patlamasi onlenir. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct policy_key);
} key_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct audit_event);
} event_scratch SEC(".maps");

/* Mutlak yol cozumleme
 *
 * bpf_d_path KULLANILMAZ. Sebebi: bu proje libbpf 1.3.0 ile
 * derleniyor ve bpf_d_path global bir fonksiyon pointer'i olarak
 * tanimli. BPF'ye cagri olarak derlendiginde hedef tampona yazim
 * IKI konuma birden duser: dogru offset (yol alani) ve 242 byte
 * kaymis konum. Sonuc yol alani bozulur, hash eslesmesi hicbir
 * zaman tutmaz ve kurallar sessizce uygulanmaz.
 *
 * Cozum: yol alani AX_PATH_DEPTH adet SABIT bloga bolunur
 * (struct policy_key.path, yukarida). Dentiry zincirindeki her
 * bilesen d = 0, 1, 2 ... sirasiyla blok
 * (AX_PATH_DEPTH - 1 - d) icine yazilir. Blok ofseti derleme
 * zamaninda sabittir ve okuma boyutu da sabittir, bu yuzden
 * verifier hedef+boyut sinirini statik gorur.
 *
 * Bolme ve birlestirme Go tarafinda yapilir
 * (maps.setKeyPath, audit.JoinPath). Anahtar toplam boyutu
 * degismez: 16 + 8*32 + 4 = 276.
 *
 * Tasarim kurallari (bozmadan once okuyun):
 *   1. Hedef ve boyut her zaman sabit olmali. Calisma aninda
 *      hesaplanan &key->path[pos] verifier tarafindan reddedilir.
 *   2. Iki gecis de unroll'lenmeli. Runtime dongude verifier
 *      dongu govdesini her yineleme icin yeniden dogruluyor ve
 *      program 1M instruction sinirini asiyor. Ic ice unroll ise
 *      512 byte stack sinirini asiyor.
 *   3. bpf_probe_read_kernel_str kullanmayin: icinde 256 adimlik
 *      gizli unroll vardir.
 *   4. Kok bilesen yazilmaz. Go tarafi da kok uretmez; yazilirsa
 *      blok 0'da "//" olur ve anahtarlar eslesmez.
 */

/* bprm_check_security iki anahtari ayni anda sorgular. Ikinci
 * anahtar (surec kurali) burada tutulur: ayri bir ax_key()
 * cagrisi ek bir bpf_map_lookup_elem demek ve verifier'in
 * instruction patlamasini tetikliyor. */
struct path_buf {
	struct policy_key skey;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct path_buf);
} path_scratch SEC(".maps");

static __always_inline struct path_buf *ax_pathbuf(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&path_scratch, &z);
}

/* Mutlak yol cozumleme
 *
 * bpf_d_path KULLANILMAZ: bu proje libbpf 1.3.0 ile derleniyor
 * ve bpf_d_path global bir fonksiyon pointer'i olarak tanimli.
 * BPF'ye cagri olarak derlendiginde hedef tampona yazim IKI
 * konuma birden duser (dogru offset + 242 byte kaymis konum).
 * Sonuc: yol alani bozulur, hash eslesmesi hicbir zaman
 * tutmaz ve tum yol bazli kurallar sessizce uygulanmaz.
 *
 * Cozum: yol alani AX_PATH_DEPTH adet SABIT bloga bolunur
 * (struct policy_key.path, yukarida). Dentiry zincirindeki her
 * bilesen d = 0, 1, 2 ... sirasiyla blok
 * (AX_PATH_DEPTH - 1 - d) icine yazilir. Blok ofseti derleme
 * zamaninda sabittir ve okuma boyutu da sabittir, bu yuzden
 * verifier hedef+boyut sinirini statik gorur:
 *   - calisma aninda hesaplanan hedef+boyut ikilisi YOK
 *   - runtime dongu YOK (unroll) -> instruction patlamasi yok
 *
 * Bolme ve birlestirme Go tarafinda yapilir
 * (maps.setKeyPath, audit.JoinPath). Anahtar toplam boyutu
 * degismez: 16 + 8*32 + 4 = 276.
 */
/* Gorunmez mount kozu mu? (axdaemon mountinfo'dan doldurur.)
 *
 * btrfs'te kok alt birim oldugunda dentry zincirine "root" gibi
 * gorunmez bir bilesen girer; gorunur yolda yoktur ve atlanmalidir.
 * /var ve /home gibi ayri alt birim mount'larinin koklari ise
 * gorunur yolun parcasidir ve KORUNUR.
 */
static __always_inline int ax_mount_artifact(const char *name)
{
	__u8 *v;

	v = bpf_map_lookup_elem(&mount_artifact_map, name);
	return v != 0;
}

/* Dentry yurusunden gelen bilesenleri path bloklarina yazar.
 *
 * base, yolun EN YUKSEK blogu (dosyanin kendi adinin oturdugu
 * blok). Derleme zamani sabiti oldugu icin tum ofkezler sabit
 * olur ve verifier sinir denetimi gerektirmez.
 *
 * Ayri bir __always_inline fonksiyon olmasi kasitlidir: switch
 * her kolunde FARKLI bir base ile cagrilir, derleyici her
 * birini ayri gomulur ve her gomulmede ofkezler sabitlesir.
 */
static __always_inline void ax_write_components(struct path *p,
						struct policy_key *key,
						__u32 base,
						struct dentry *mnt_root)
{
	struct dentry *cur;
	struct dentry *up;
	const unsigned char *nm;
	char artkey[AX_PATH_SLOT];
	int len, d;

	cur = BPF_CORE_READ(p, dentry);
	if (!cur)
		return;
#pragma unroll
	for (d = 0; d < AX_PATH_DEPTH; d++) {
		__u32 b = base - (__u32)d;

		if ((__u32)d >= base)
			break;
		up = BPF_CORE_READ(cur, d_parent);
		nm = BPF_CORE_READ(cur, d_name.name);
		if (!nm)
			break;
		len = BPF_CORE_READ(cur, d_name.len);
		if (len <= 0 || len > AX_NAME_MAX)
			break;

		/* Kok dentry hicbir bloga yazilmaz. Go tarafi da kok
		 * icerigi uretmez; iki taraf ayni anahtari uretmek
		 * icin burada da yazmak sart. */
		if (!up || up == cur)
			break;

		__builtin_memset(key->path[b], 0, AX_PATH_SLOT);
		key->path[b][0] = '/';
		if (bpf_probe_read_kernel(&key->path[b][1], AX_NAME_MAX,
					  nm) < 0)
			return;

		__builtin_memset(artkey, 0, sizeof(artkey));
		__builtin_memcpy(artkey, key->path[b] + 1, AX_NAME_MAX);

		/* Gorunmez mount kozu mu? (axdaemon mountinfo'dan
		 * doldurur.)  /etc -> "root" atlanir; /var -> "var"
		 * korunur.
		 *
		 * Bolme isareti HARITAYA GIRMEZ; Go tarafi mount
		 * kokunun adini dogrudan yazar.
		 *
		 * Koz bilesenini TAMAMEN sil.
		 *
		 * Yalnizca path[b][0] = '\0' yapmak YETMEZ: Go tarafi
		 * her blogu "/ad" biciminde bekler ve ilk bayti NUL
		 * olsa bile adin geri kalini birlestiriyor. Audit
		 * ciktisi bunu acikca gosterdi:
		 *   "path":"\u0000root/etc/ax-r3"
		 * Yani anahtar "/\0root/etc/ax-r3" oluyor ve hicbir
		 * politika anahtariyla eslesmiyor.
		 *
		 * Blogun TAMAMI temizlenir; Go bos blogu atlar. */
		if (cur == mnt_root && ax_mount_artifact(artkey))
			__builtin_memset(key->path[b], 0, AX_PATH_SLOT);
		cur = up;
	}
}

static __always_inline int ax_fill_path(struct path *p, struct policy_key *key)
{
	struct dentry *cur;
	struct dentry *up;
	const unsigned char *nm;
	struct vfsmount *mnt;
	struct dentry *mnt_root = 0;
	/* Mount noktasi oneki.
	 *
	 * Harita degeri bir yigin tamponuna kopyalanmaz; arama
	 * yapildigi anda (gecis 1, baska map cagrisi YOK) yazilir.
	 * Gecis 2'de her bilesende mount_artifact_map'e bakildigi
	 * icin harita degeri o noktada verifier'da gecersizdir. */
	__u32 nprefix = 0;
	__u32 ncomp = 0;
	__u32 total;
	int len, d;

	/* Bu yolun mount koku. Koz bileseni SADECE gercekten mount
	 * koku oldugunda atilir.
	 *
	 * Ad tek basina yetmez: /root dizinin adi de "root"tur.
	 * Ada bakarak atilirsa /root altindaki kurallar da sessizce
	 * calismaz. Iki kosun birlikte (ad haritada VE bilesen mount
	 * koku) ayrimi kesin yapar:
	 *
	 *   /etc/ax-f  -> "root" == mnt_root  -> ATLA   (dogru)
	 *   /root/ax-f -> "root" != mnt_root  -> KAL    (dogru)
	 *   /var/ax-f  -> "var" haritada yok  -> KAL    (dogru)
	 */
	mnt = BPF_CORE_READ(p, mnt);
	if (mnt)
		mnt_root = BPF_CORE_READ(mnt, mnt_root);

	/* Harita anahtari icin temiz tampon.
	 *
	 * DOGRUDAN `key->path[b] + 1` ADRESI KULLANILAMAZDI: harita
	 * anahtar boyutu 32 bayt, slot 32 bayt ve bastaki '/'
	 * atlandiginda 31 kalir. Harita 32 bayt okudugu icin bir
	 * sonraki slotun '/' karakteri anahtarin icine karisiyor ve
	 * Go tarafinin yazdigi "root" + NUL dolgusuyla ESLESMIYOR.
	 * Go'nun bittigi yerde bpf sifiri gorur; "root" hicbir zaman
	 * bulunamaz ve /etc kurallari sessizce calismaz.
	 *
	 * Bu yuzden ad once NUL ile dolu 32 baytlik tampona kopyalanir.
	 */
	if (!p)
		return -1;

	/* --- ALT BIRIM KOKU TESPITI ---
	 *
	 * Fedora'da kok, btrfs ALT BIRIM olarak baglanir:
	 *
	 *   subvol 256 gen ... top level 5 path root
	 *   subvol 258 gen ... top level 5 path home
	 *   subvol 259 gen ... top level 5 path var
	 *
	 * Bu duzende gorunur yola "root" GIRMEZ:
	 *
	 *   /etc/ax-t7  ->  ax-t7 -> etc -> root -> /
	 *                     (gorunur yol: /etc/ax-t7)
	 *
	 * "root" yazilirsa yol "/root/etc/ax-t7" olur; politika ise
	 * "/etc/ax-t7" yazar. Anahtarlar kesismez ve kural HICBIR
	 * SEYI UYGULAMAZ.
	 *
	 * ONCEDEN inode/super_block sezgisi kullaniliyordu
	 * (self_ino == up_ino && sroot != cur). Bu HATALIYDI:
	 * btrfs dizin inode'larini alt birim kokunden verir, bu
	 * yuzden /var ve /home de ayni sezgiyi tetikliyor ve
	 * GORUNUR bilesenler atiliyordu:
	 *
	 *   /var/ax-t7  ->  ax-t7 -> var -> /     ("var" atildi -> HATA)
	 *   /home/ax-t7 ->  ax-t7 -> home -> /    ("home" atildi -> HATA)
	 *
	 * DOGRU AYIRT EDICI: mount KOKUNUN ADI.
	 *
	 *   - Kok mount (/): mnt_root adi "/"  -> atlanacak bilesen yok
	 *     veya alt birim kozu "root" gibi cok harfli bir ad.
	 *   - Alt mount (/tmp, /var ayri mount ise): mnt_root adi
	 *     kendi adi ("tmp", "var") ve o ad GORUNUR yolun bir
	 *     parcasidir; ATLANMAZ.
	 *
	 * Ayrica yalnizca KOK mount'un (mnt_parent == mnt) koku
	 * gecen kisim atlanir. Bir alt mount'un koku, mount noktasinin
	 * gorunur adidir ve yola dahildir.
	 *
	 * Bu ayirt edici sayesinde uc durum da dogru cozulur:
	 *   /etc  -> "root" atlanir  -> /etc/...      (dogru)
	 *   /var  -> hicbiri atlanmaz -> /var/...      (dogru)
	 *   /tmp  -> hicbiri atlanmaz -> /tmp/...      (dogru)
	 */
	/* Gecis 1: toplam uzunluk (yazma yok) */
	cur = BPF_CORE_READ(p, dentry);
	if (!cur)
		return -2;

	total = 0;
#pragma unroll
	for (d = 0; d < AX_PATH_DEPTH; d++) {
		up = BPF_CORE_READ(cur, d_parent);
		nm = BPF_CORE_READ(cur, d_name.name);
		if (!nm)
			break;
		len = BPF_CORE_READ(cur, d_name.len);
		if (len <= 0 || len > AX_NAME_MAX)
			break;
		/* Kok dentry Go tarafinda bloga yazilmaz; sayma.
		 *
		 * Burada mount noktasi oneki ARANIR. Dentry yurusu
		 * mount kokunde biter ve o noktada "tmp" gibi bir
		 * mount noktasi adi YOKTUR (mount bir dizin girdisi
		 * degil, bir baglantidir). Bu yuzden onek haritadan
		 * alinir ve yolun ALTINA eklenir.
		 *
		 * Arama yalnizca burada, ilk gecis icinde yapilir:
		 * (a) bu noktada baska map cagrisi YOK, dogrudan
		 *     stack'e kopyalanabilir; (b) gecis 2'de her
		 *     bilesende mount_artifact_map'e bakiliyor ve
		 *     verifier o cagrilarin pointer'lari bozdugu icin
		 *     harita degeri gecersizlesirdi. */
		if (!up || up == cur) {
			struct ax_mp_key mk;
			struct ax_mp_val *mpv;

			/* d_inode ve i_sb ISARECI'dir; BPF_CORE_READ noktali
			 * erisimi degil zincir kabul eder. */
			mk.dev = BPF_CORE_READ(cur, d_inode, i_sb, s_dev);
			mpv = bpf_map_lookup_elem(&mount_point_map, &mk);
			if (mpv) {
				__u32 np = mpv->n;

				/* verifier icin araligi ACIKCA daralt:
				 * 1 <= np <= 4. Bu olmadan blok indeksi
				 * kanitlanamiyor ve program "R4 unbounded
				 * memory access" ile reddediliyordu. */
				if (np > AX_MP_MAX)
					np = AX_MP_MAX;
				if (np >= 1 && ncomp + np <= (__u32)AX_PATH_DEPTH) {
					nprefix = np;
					total += mpv->bytes;
					/* b = 8 - np + i, np in [1,4], i in
					 * [0,3] -> b in [4,7]. */
				/* Onek, bilesenlerin ALTINDA durmalidir.
				 *
				 * Go tarafi setKeyPath("/tmp/ax-pintest") su
				 * duzeni uretir:
				 *     Path[7]="/ax-pintest"   <- en derin bilesen
				 *     Path[6]="/tmp"          <- mount noktasi
				 *
				 * Bilesenler 7'den ASAGI, onek onlarin
				 * altina yazilir. Ilk denemede onek 7'ye
				 * yaziliyordu ve anahtar TERS kuruluyordu.
				 *
				 * Ofkez ncomp'a bagli; ncomp yigin
				 * degiskeni oldugu icin switch ile derleme
				 * zamaninda sabitlestirilir. */
				/* Onek, bilesenlerin ALTINDA durmalidir ve YOL
				 * YONUNDE TERS sirada yazilir.
				 *
				 * Go tarafi setKeyPath("/dev/shm/ax-f") su duzeni
				 * uretir:
				 *     Path[7]="/ax-f"  Path[6]="/shm"  Path[5]="/dev"
				 *
				 * Yani mount noktasi onceki slotlarindan geriye
				 * dogru siralanir ve Go tarafi slot[] dizisini de
				 * TERS doldurur (bkz. buildMountPointVal).
				 *
				 * Ilk iki denemede ya onek bilesenlerin USTUNE
				 * yaziliyordu ya da ayni yonde siraliyordu;
				 * /tmp tek bilesenli oldugu icin dogru gorunuyor,
				 * /dev/shm ve /run/user/1000 ise tutmuyordu.
				 */
				switch (ncomp) {
				case 0:
					if (nprefix > 0)
						__builtin_memcpy(key->path[7], mpv->slot[0], AX_PATH_SLOT);
					if (nprefix > 1)
						__builtin_memcpy(key->path[6], mpv->slot[1], AX_PATH_SLOT);
					if (nprefix > 2)
						__builtin_memcpy(key->path[5], mpv->slot[2], AX_PATH_SLOT);
					if (nprefix > 3)
						__builtin_memcpy(key->path[4], mpv->slot[3], AX_PATH_SLOT);
					break;
				case 1:
					if (nprefix > 0)
						__builtin_memcpy(key->path[6], mpv->slot[0], AX_PATH_SLOT);
					if (nprefix > 1)
						__builtin_memcpy(key->path[5], mpv->slot[1], AX_PATH_SLOT);
					if (nprefix > 2)
						__builtin_memcpy(key->path[4], mpv->slot[2], AX_PATH_SLOT);
					if (nprefix > 3)
						__builtin_memcpy(key->path[3], mpv->slot[3], AX_PATH_SLOT);
					break;
				case 2:
					if (nprefix > 0)
						__builtin_memcpy(key->path[5], mpv->slot[0], AX_PATH_SLOT);
					if (nprefix > 1)
						__builtin_memcpy(key->path[4], mpv->slot[1], AX_PATH_SLOT);
					if (nprefix > 2)
						__builtin_memcpy(key->path[3], mpv->slot[2], AX_PATH_SLOT);
					if (nprefix > 3)
						__builtin_memcpy(key->path[2], mpv->slot[3], AX_PATH_SLOT);
					break;
				case 3:
					if (nprefix > 0)
						__builtin_memcpy(key->path[4], mpv->slot[0], AX_PATH_SLOT);
					if (nprefix > 1)
						__builtin_memcpy(key->path[3], mpv->slot[1], AX_PATH_SLOT);
					if (nprefix > 2)
						__builtin_memcpy(key->path[2], mpv->slot[2], AX_PATH_SLOT);
					if (nprefix > 3)
						__builtin_memcpy(key->path[1], mpv->slot[3], AX_PATH_SLOT);
					break;
				case 4:
					if (nprefix > 0)
						__builtin_memcpy(key->path[3], mpv->slot[0], AX_PATH_SLOT);
					if (nprefix > 1)
						__builtin_memcpy(key->path[2], mpv->slot[1], AX_PATH_SLOT);
					if (nprefix > 2)
						__builtin_memcpy(key->path[1], mpv->slot[2], AX_PATH_SLOT);
					if (nprefix > 3)
						__builtin_memcpy(key->path[0], mpv->slot[3], AX_PATH_SLOT);
					break;
				case 5:
					if (nprefix > 0)
						__builtin_memcpy(key->path[2], mpv->slot[0], AX_PATH_SLOT);
					if (nprefix > 1)
						__builtin_memcpy(key->path[1], mpv->slot[1], AX_PATH_SLOT);
					if (nprefix > 2)
						__builtin_memcpy(key->path[0], mpv->slot[2], AX_PATH_SLOT);
					break;
				case 6:
					if (nprefix > 0)
						__builtin_memcpy(key->path[1], mpv->slot[0], AX_PATH_SLOT);
					if (nprefix > 1)
						__builtin_memcpy(key->path[0], mpv->slot[1], AX_PATH_SLOT);
					break;
				case 7:
					if (nprefix > 0)
						__builtin_memcpy(key->path[0], mpv->slot[0], AX_PATH_SLOT);
					break;
				default:
					break;
				}

				}
				/* Bilesenler + onek sigmiyorsa onek
				 * yazilmaz. Yarim yazilmis yol, hic
				 * yazilmamis yoldan daha kotudur. */
			}
			break;
		}

		total += len + 1;
		ncomp++;
		cur = up;
	}

	if (total > (__u32)MAX_PATH_LEN)
		return -3;

	/* Gecis 2: her bilesen SABIT bloguna yazilir.
	 *
	 * d = 0 dosyanin kendi adidir ve yolun SON ogesidir, bu
	 * yuzden en yuksek bloga yazilir.
	 *
	 * Mount noktasi oneki varsa blok tabani onek kadar ASAGI
	 * kayar: /tmp/ax-pintest 2 bilesen + 1 onek blogu ister ve
	 * sirayla
	 *     Path[7]="/ax-pintest"  Path[6]="/tmp"
	 * yazilir. Go tarafi setKeyPath() ayni sirayi uretir.
	 *
	 * BASE derleme zamani SABIT olarak verilir (switch asagida).
	 * Bunun nedeni verifier: nprefix bir yigin degiskenidir ve
	 * "8 - nprefix + i" gibi ifadelerin sonucunu kanitlayamaz.
	 * Ilk denemede program "R4 unbounded memory access" ile
	 * reddedildi (offset 272 = path[8], tam bir blok tasmasi).
	 * Sabit ofkezle bu tur bir hata tamamen ortadan kalkar.
	 */
	ax_write_components(p, key, 7, mnt_root);

	/* Kok bos ise tum bloklar temiz kalsin.
	 *
	 * DIKKAT: onek + bilesenler 0. blogu da kullanabilir
	 * (toplam 8 bilesende). O durumda 0. blogu silmek GERCEK
	 * bir yol bilesenini yok ederdi. */
	if (ncomp + nprefix < (__u32)AX_PATH_DEPTH)
		key->path[0][0] = '\0';
	return 0;
}

/* Yardimcilar */

static __always_inline struct policy_key *ax_key(__u32 slot)
{
	__u32 k = slot;
	return bpf_map_lookup_elem(&key_scratch, &k);
}

static __always_inline struct audit_event *ax_event(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&event_scratch, &zero);
}

static __always_inline void ax_get_comm(char *comm)
{
	bpf_get_current_comm(comm, 16);
}

/* comm ile verilen ismi karsilastirir. */
static __always_inline int ax_comm_is(const char *comm, const char *name)
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (name[i] == '\0')
			return comm[i] == '\0';
		if (comm[i] != name[i])
			return 0;
	}
	return 1;
}

/* Sistem kilitlenmesini onleyen koruma.
 *
 * Bir kural init, sshd, login, sudo veya bash gibi kritik bir
 * surece uygulandiginda sistem kendini kilitler: o surecin tum
 * cocuk surecleri de engellenir, oturum kapanir ve kurtarma icin
 * kullaniciya "reboot edin"den baska yol kalmaz. Bu, MAC'in en
 * tehlikeli hata modudur.
 *
 * Bu yuzden asagidaki surecler hicbir kurala tabi DEGILDIR;
 * programlar onlar icin dogrudan 0 doner. Policy "bash /bin/echo
 * calistiramaz" dese bile bash kendi oturumunu acabilir, sudo
 * calisir ve mod degistirilebilir.
 *
 * Liste bilincli olarak kisadir; her aday su iki sorudan gecer:
 *   1) engellersem sisteme tekrar erisebilir miyim?
 *   2) bu kisisel bir kullanici uygulamasi mi?
 * "hayir" veya "evet" cevabi olan aday listeye GIRMEZ.
 */
/* Korumali surec kontrolu.
 *
 * ONCEDEN burada `bpf_get_current_pid_tgid() >> 32 <= 2` kontrolu
 * vardi. KALDIRILDI.
 *
 * SORUN (Fedora 44 / clang 22 / kernel 6.19):
 *   At program exit the register R0 has smin=0 smax=4294967295
 *   should have been in [-4095, 0]
 *
 * LSM kancasi birden fazla `return` icerir (0 ve -EPERM). clang 22
 * bunleri tek bir stack degiskeninde birlestirir. PIDden gelen
 * bir skaler bu degere katilip yiginda tasindiginda, program sonu
 * `r0 = *(u32 *)(r10-8)` ile yukler; yukleme ISARETsiz oldugu icin
 * verifier araligi 0..4294967295 gorur ve program reddeder.
 *
 * Ayri ayri dogrulandi:
 *   - yalnizca PID kontrolu iceren surum    -> BASARISIZ
 *   - yalnizca isim karsilastirmasi iceren -> VERIFIER_OK
 *
 * Sonuc: program YUKLENMEZ; daemon "ebpf yuklenemedi, yalnizca RPC
 * calisiyor" deyip enforcement OLMADAN calismaya devam eder. Kurulum
 * "basarili" gorunur ama sistemde hicbir sey engellenmez.
 *
 * PID 1 ve PID 2 KONTROLU ZATEN ADLA COZULUYOR:
 *   PID 1 -> comm "systemd" (veya erken acilista "init"/"swapper")
 *   PID 2 -> comm "kthreadd"
 * Bunlarin hepsi asagidaki listede. Yani PID kontrolu GEREKSIZDI;
 * kaldirmak guvenlikte kayip yaratmaz, sadece hatayi giderir.
 * "swapper" ve "migration" de listeye eklendi (PID 1/2'nin erken
 * acilistaki adi).
 */

static __always_inline int ax_protected(const char *comm)
{
	/* [2] Yetki yukseltme ve oturum acma zinciri. */
	/* "swapper" ve "migration" PID 1'in erken acilistaki adi
	 * olabilir; once sayimsal PID kontrolu varken bu gerekli
	 * degildi. PID kontrolu kaldirildigi icin burada tutuluyor. */
	if (ax_comm_is(comm, "swapper") ||
	    ax_comm_is(comm, "migration") ||
	    ax_comm_is(comm, "systemd") ||
	    ax_comm_is(comm, "systemd-logind") ||
	    ax_comm_is(comm, "systemd-userdbd") ||
	    ax_comm_is(comm, "systemd-udevd") ||
	    ax_comm_is(comm, "systemd-journald") ||
	    ax_comm_is(comm, "systemd-oomd") ||
	    ax_comm_is(comm, "init") ||
	    ax_comm_is(comm, "kthreadd") ||
	    ax_comm_is(comm, "sshd") ||
	    ax_comm_is(comm, "sshd-session") ||
	    ax_comm_is(comm, "login") ||
	    ax_comm_is(comm, "agetty") ||
	    ax_comm_is(comm, "getty") ||
	    ax_comm_is(comm, "sudo") ||
	    ax_comm_is(comm, "su") ||
	    ax_comm_is(comm, "doas") ||
	    ax_comm_is(comm, "dbus-daemon") ||
	    ax_comm_is(comm, "dbus-broker") ||
	    ax_comm_is(comm, "polkitd") ||
	    ax_comm_is(comm, "rtkit-daemon") ||
	    ax_comm_is(comm, "NetworkManager") ||
	    ax_comm_is(comm, "wpa_supplicant") ||
	    ax_comm_is(comm, "gdm3") ||
	    ax_comm_is(comm, "gdm-session-worke"))
		return 1;

	/* [3] Kullanici oturumu: kabuklar.
	 *
	 * BURALARDI her sey bloklanirsa oturum kapanir ve kurtarma
	 * icin reboot'tan baska yol kalmaz. Kabuk engellenirse
	 * kullanici sudo, axctl ya da mod degisikligi ile duzeltebilir. */
	if (ax_comm_is(comm, "bash") ||
	    ax_comm_is(comm, "sh") ||
	    ax_comm_is(comm, "dash") ||
	    ax_comm_is(comm, "zsh") ||
	    ax_comm_is(comm, "fish"))
		return 1;

	/* [4] Bilerek KORUNMAYANLAR
	 *
	 * tmux/screen, editor ve dil kosullari (node, npm, bun, deno,
	 * python3, python, perl, ruby, code, opencode, gopls,
	 * rust-analyzer) listede DEGILDIR.
	 *
	 * Gerekce: bunlari korumak MAC'i islevsizlestirir. Cogu gercek
	 * uygulama bir yorumlayicidan calisir; "python3 /etc/shadow
	 * okuyamaz" veya "node aga cikamaz" MAC'in en sik kullanilan
	 * ve EN ACIL kural turleridir. Bu kurallari yazamamak, urunu
	 * kullanilamaz hale getirir.
	 *
	 * Bunlari engellemek kilitlenme de YARATMAZ: kullanici hala
	 * korumali bir kabuga (bash/sh) sahiptir ve oradan modu
	 * degistirebilir. Yani korumanin tek islevi - kurtarma yolunu
	 * (kabuk, oturum acma, yetki yukseltme) acik tutmak - bu
	 * surecler icin gerekli degildir.
	 *
	 * tmux/screen de korunmaz: onlar konfor araci, kurtarma yolu
	 * degil. tmux engellendi diye bash hala durur.
	 */

	return 0;
}

/* Portu "p:<port>" ASCII bicimine yazar.
 *
 * Go tarafi fmt.Sprintf("p:%d", port) ile AYNI metni uretir: basamak
 * sayisi kadar yazilir, sola sIkistirILMAZ.
 *
 * Burada daha once sabit 5 hane yaziliyordu ("p:00080"). Go ise
 * "p:80" uretiyordu; 80 ve 443 gibi gercek portlarda anahtarlar
 * hicbir zaman eslesmez ve ag kurallari sessizce uygulanmazdi.
 * Yalnizca 45678 gibi tam 5 haneli test portlari kazara tutuyordu.
 *
 * Yazim sola duz (birebir) ilerler: en yuksek basamak once.
 * T donguleri unroll'lenir (toplam 5+1+5 = 11 dongu); calisma aninda
 * indekslenen hedef yoktur, verifier sinirlari statik gorur.
 */
static __always_inline int ax_set_port(char *slot, __u16 hport)
{
	unsigned int v = hport;
	int i = 2;

	slot[0] = 'p';
	slot[1] = ':';

	/* Asagi en yuksek basamak: 10000, 1000, 100, 10, 1.
	 * Her adimda v >= bolen ise o basamak yazilir. */
	#pragma unroll
	for (int place = 4; place >= 0; place--) {
		unsigned int div = 1;
		#pragma unroll
		for (int m = 0; m < 4; m++) {
			if (m < place)
				div *= 10;
		}
		if (v >= div) {
			slot[i] = (char)('0' + ((v / div) % 10));
			i++;
		}
	}

	slot[i] = '\0';
	return i;
}

/* Bos yol: tum bloklar sifir, ilk blok bos birak. */
static __always_inline void ax_clear_path(struct policy_key *key)
{
	__builtin_memset(key->path, 0, sizeof(key->path));
}

static __always_inline __u32 ax_mode(void)
{
	__u32 key = 0;
	__u32 *mode = bpf_map_lookup_elem(&mode_map, &key);

	if (!mode)
		return MODE_ENFORCING;
	return *mode;
}

/* Ogrenme modu acik mi? Kancalar bunu, izin verilen
 * operasyonlari da audit olayina cevirmek icin sorar. */
static __always_inline int ax_learning(void)
{
	__u32 key = 0;
	__u32 *on = bpf_map_lookup_elem(&learn_map, &key);

	return on && *on;
}

/* deny_map once bakilir, sonra allow_map. Bulunamazsa NULL. */
static __always_inline struct policy_value *ax_lookup(struct policy_key *key)
{
	struct policy_value *val;

	val = bpf_map_lookup_elem(&deny_map, key);
	if (val)
		return val;

	val = bpf_map_lookup_elem(&allow_map, key);
	if (val)
		return val;

	return NULL;
}

/* subject: "*" (JOKER) DESTEGI.
 *
 * Go tarafi joker kurali haritaya comm = "*" olarak yazar.
 * BPF tarafi ise anahtari gercek surec adiyle doldurur
 * ("curl", "cat", "python3"). Bu yuzden joker kural HICBIR
 * ZAMAN eslesmiyordu:
 *
 *   subject: "*"  object: /etc/ax-secret  action: file.read
 *     -> kural haritada var (deny_map kayit: 1)
 *     -> "policy check" gecer
 *     -> reload "basarili" der
 *     -> ama dosya OKUNUR
 *
 * Politika dilinin en kotu turu: kullanici kuralini yazdigini
 * sanir, sistem sessizce hicbir sey yapmaz.
 *
 * Cozum: tam eslesme bulunamazsa ayni yol/eylem, comm = "*"
 * ile bir kez daha aranir.
 *
 * Joker, tam eslesmeden SONRA bakilir. Boylece belirli bir
 * kural ("curl") jokeri gecersiz kilabilir.
 *
 * Anahtar 1. yuvaya (key_scratch slot 1) yazilir; slot 0
 * (cagiranin kullandigi) BOZULMEZ. Ayni yuvayi yazmak
 * sonraki kancalarin yolunu bozardi.
 */
static __always_inline struct policy_value *
ax_lookup_wild(struct policy_key *key)
{
	struct policy_value *val;
	struct policy_key *wkey;
	int i;
	int is_star;

	/* 1) Tam eslesme (mevcut davranis, DEGISMEDI) */
	val = ax_lookup(key);
	if (val)
		return val;

	is_star = (key->comm[0] == '*' && key->comm[1] == '\0');

	/* 2) subject: "*" (JOKER)
	 *
	 * Go tarafi joker kurali comm="*" yazar; BPF tarafi gercek
	 * surec adini ("curl") yazar. Tam eslesme bulunamaz.
	 *
	 * Joker, tam eslesmeden SONRA bakilir; belirli bir kural
	 * ("curl") jokeri gecersiz kilabilir.
	 *
	 * Anahtar slot 1'e yazilir; slot 0 BOZULMEZ (sonraki
	 * kancalarin yolunu bozardi).
	 */
	/* Anahtar zaten joker ise tekrar aramaya gerek yok.
	 * (Once `is_star` hesaplaniyor ama KULLANILMIYORDU: hem
	 *  derleyici uyarisi veriyordu hem de ayni anahtar ikinci kez
	 *  araniyordu.) */
	if (is_star)
		return NULL;

	wkey = ax_key(1);
	if (wkey) {
		__builtin_memcpy(wkey, key, sizeof(*wkey));
#pragma unroll
		for (i = 0; i < TASK_COMM_LEN; i++)
			wkey->comm[i] = '\0';
		wkey->comm[0] = '*';
		val = ax_lookup(wkey);
		if (val)
			return val;
	}

	return NULL;
}

/* Iki anahtarli DENY aramasi. Iki ayri ax_lookup cagrisi
 * verifier'da instruction patlamasina yol actigi icin tek
 * fonksiyonda birlestirilir; ayni kancada ucten fazla arama
 * yapilmamalidir.
 */
static __always_inline struct policy_value *ax_lookup2(
	struct policy_key *k1, struct policy_key *k2)
{
	struct policy_value *v;
	struct policy_key *wkey;
	int i;
	int is_star;

	/* Tam eslesmeler */
	v = bpf_map_lookup_elem(&deny_map, k1);
	if (v)
		return v;
	v = bpf_map_lookup_elem(&deny_map, k2);
	if (v)
		return v;

	/* Joker (subject: "*") aramalari.
	 *
	 * ONCEDEN YOKTU. Bu yuzden bprm kancasinda
	 *   subject: "*"  +  object: /usr/bin/id
	 * turu file.execute kurallari HIC UYGULANMIYORDU: BPF gercek
	 * surec adini ("timeout") yazar, Go ise joker kurali comm="*"
	 * ile yazar; tam eslesme olmadigi icin kurala hic ulasilamaz.
	 *
	 * inode_permission kanitasi zaten ax_lookup_wild()
	 * kullaniyor; bprm kanitasi ise yalnizca ax_lookup2()
	 * cagriyordu. Lencisi tutarsizdi.
	 *
	 * Joker, tam eslesmeden SONRA bakilir; belirli bir kural
	 * ("curl") jokeri gecersiz kilabilir.
	 */
#pragma unroll
	for (i = 0; i < 2; i++) {
		struct policy_key *k = i ? k2 : k1;

		is_star = (k->comm[0] == '*' && k->comm[1] == '\0');
		if (is_star)
			continue;

		/* Anahtar slot 1'e yazilir; slot 0 BOZULMEZ
		 * (sonraki kancalarin yolunu bozardi). */
		wkey = ax_key(1);
		if (!wkey)
			continue;
		__builtin_memcpy(wkey, k, sizeof(*wkey));
#pragma unroll
		for (int j = 0; j < TASK_COMM_LEN; j++)
			wkey->comm[j] = '\0';
		wkey->comm[0] = '*';
		v = bpf_map_lookup_elem(&deny_map, wkey);
		if (v)
			return v;
	}

	return NULL;
}

/* Audit olayini perf buffer'a yazar.
 *
 * bpf_perf_event_output(ctx, map, flags, data, size) imzasi ilk
 * argumani program ctx'si ister. ctx olamayan bir yardimciya
 * gecirildiginde verifier "R1 type=map_value expected=ctx" ile
 * programi reddeder; bu yuzden her kanca ctx'yi gecmelidir.
 */
static __always_inline void ax_audit(void *ctx, struct audit_event *event)
{
	event->timestamp = bpf_ktime_get_ns();
	bpf_perf_event_output(ctx, &audit_buffer, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));
}

#endif /* __AXBPF_H */
