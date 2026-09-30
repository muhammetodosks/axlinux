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
static __always_inline int ax_fill_path(struct path *p, struct policy_key *key)
{
	struct dentry *cur;
	struct dentry *up;
	const unsigned char *nm;
	__u32 total;
	int len, d;

	/* key per-CPU array degeri: bpf_map_lookup_elem NULL donmez.
	 * NULL kontrolu verifier'a "pointer 0 olabilir" dediginden
	 * sonraki yazmalarda offset sinirini kaybediyordu. */
	if (!p)
		return -1;

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
		/* kok dentry Go tarafinda bloga yazilmaz; sayma */
		if (!up || up == cur)
			break;
		total += len + 1;
		cur = up;
	}
	if (total > (__u32)MAX_PATH_LEN)
		return -3;

	/* Gecis 2: her bilesen SABIT bloguna yazilir.
	 * d = 0 dosyanin kendi adidir ve yolun SON ogesidir, bu
	 * yuzden en yuksek bloga yazilir. Blok ofseti derleme
	 * zamaninda sabittir; hedef ve boyut sabit oldugu icin
	 * verifier'in istedigi sinirlar statik olarak gorunur. */
	cur = BPF_CORE_READ(p, dentry);
	#pragma unroll
	for (d = 0; d < AX_PATH_DEPTH; d++) {
		__u32 b = (__u32)(AX_PATH_DEPTH - 1 - d);

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
			return -6;
		cur = up;
	}

	/* kok bos ise tum bloklar temiz kalsin */
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
static __always_inline int ax_protected(const char *comm)
{
	/* [1] Calisma ortamini tasiyan cekirdek surecleri. */
	if ((bpf_get_current_pid_tgid() >> 32) <= 2)
		return 1;

	/* [2] Yetki yukseltme ve oturum acma zinciri. */
	if (ax_comm_is(comm, "systemd") ||
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

/* Iki anahtarli DENY aramasi. Iki ayri ax_lookup cagrisi
 * verifier'da instruction patlamasina yol actigi icin tek
 * fonksiyonda birlestirilir; ayni kancada ucten fazla
 * bpf_map_lookup_elem zinciri kullanilmamalidir. */
static __always_inline struct policy_value *ax_lookup2(
	struct policy_key *k1, struct policy_key *k2)
{
	struct policy_value *v;

	v = bpf_map_lookup_elem(&deny_map, k1);
	if (v)
		return v;
	v = bpf_map_lookup_elem(&deny_map, k2);
	if (v)
		return v;
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
