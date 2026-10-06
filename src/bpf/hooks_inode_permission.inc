/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/inode_permission kancası
 * inode erisim izni kontrolu (okuma / yazma / calistirma).
 */


/* MAY_READ=4, MAY_WRITE=2, MAY_EXEC=1 */
static __always_inline int mask_to_action(int mask)
{
	if (mask & 0x4)
		return ACTION_FILE_READ;
	if (mask & 0x2)
		return ACTION_FILE_WRITE;
	if (mask & 0x1)
		return ACTION_FILE_EXEC;
	return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(ax_inode_permission, struct inode *inode, int mask, int ret)
{
	struct policy_key *key = ax_key(0);
	struct audit_event *event = ax_event();
	struct policy_value *val;
	__u32 mode;
	int action;

	/* Koruma kontrolu icin PID; ayrica event->pid de
	 * bunu kullanir (bpf_get_current_pid_tgid bir kez). */
	__u32 cur_pid = bpf_get_current_pid_tgid() >> 32;

	mode = ax_mode();
	if (mode == MODE_DISABLED)
		return 0;

	if (!inode || !mask || !key || !event)
		return 0;

	action = mask_to_action(mask);
	if (!action)
		return 0;

	__builtin_memset(key, 0, sizeof(*key));
	__builtin_memset(event, 0, sizeof(*event));

	ax_get_comm(key->comm);
	key->action = action;
	/* Bu kancada yol cozumlenmez, sadece surec bazli kurallar */
	ax_clear_path(key);

	/* Kritik sistem surecleri hicbir kurala tabi degildir */
	if (ax_protected(key->comm))
		return 0;

	/* Bu kanca yol cozumlemez (ax_clear_path yukarida cagrildi),
	 * bu yuzden dizin/onek kurali aranmaz: has_path = 0. */
	val = ax_decide(key, 0);
	int denied = val && val->effect == EFFECT_DENY;

	event->pid = cur_pid;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	event->action = action;
	event->effect = denied ? EFFECT_DENY : EFFECT_ALLOW;
	event->rule_id = denied ? val->rule_id : 0;
	event->hook_type = HOOK_INODE_PERMISSION;

	/* Tek karar noktasi.
	 *
	 * Once iki ayri `return` vardi: biri "izinli" yolunda 0,
	 * biri "engellendi" yolunda -EPERM. Derleyici (clang 22,
	 * Fedora 44) bu iki cikisi TEK BIR stack degiskeninde
	 * birlestirip `return <degisken>` uretiyor; degisken
	 * isaretsiz oldugu icin yukleme `r0 = *(u32 *)(r10-8)`
	 * oluyor ve verifier araligi 0..4294967295 goruyor:
	 *
	 *   At program exit the register R0 has smin=0 smax=4294967295
	 *   should have been in [-4095, 0]
	 *
	 * LSM kancasi yalnizca 0 veya negatif dondurmelidir, program
	 * reddedilir ve YUKLENMEZ. Sonuc: daemon "ebpf yuklenemedi"
	 * deyip enforcement OLMADAN calismaya devam eder.
	 *
	 * Cozum: karar tek bir `if` icinde verilir ve fonksiyon
	 * TEK bir `return 0` ile biter. Boylece derleyicinin
	 * birlestirecegi iki farkli donus degeri kalmaz.
	 */
	if (denied) {
		if (mode == MODE_ENFORCING) {
			event->decision = DECISION_DENIED;
			ax_audit(ctx, event);
			return -EPERM;
		}
		/* permissive: kayit dus, ama izin ver */
		event->decision = DECISION_ALLOWED;
		ax_audit(ctx, event);
		return 0;
	}

	/* Izin verilen erisim icin ogrenme gozlemi.
	 *
	 * Buraya kadar yalnizca DENY kurali eslesen operasyonlar olay
	 * uretiyordu; ogrenme modunun amaci ise tam tersidir ("normalde
	 * ne yapiyorsun"). Duzeltildi.
	 *
	 * SONRA BIR DUZELTME DAHA: bu kancadan ogrenme gozlemi
	 * uretilmez.
	 *
	 * NEDEN: LSM imzasi yapici olarak `struct inode *inode` alir,
	 * `struct file *` DEGIL:
	 *
	 *   security_inode_permission(struct inode *inode, int mask)
	 *
	 * Dogrulama: /sys/kernel/btf/vmlinux -> FUNC 'security_inode_
	 * permission' proto: 'inode' type_id=1086 (struct inode).
	 *
	 * inode'in dentry'ye GERI isaretcisi YOKTUR (yön tek yönlüdur:
	 * dentry -> inode). Bu yuzden bu kancada dosya yolu CozULEMEZ.
	 * Zaten yukarida ax_clear_path(key) ile yol bilerek siliniyor.
	 *
	 * Ogrenme gozlemi ise kurallar URETMEK icin vardir ve bir kural
	 * mutlaka `object` (yol) alani icerir. Yolsuz bir gozlemden
	 * kural uretilemez. O yuzden bu kayitlar:
	 *   - bilgi tasimiyor (operator hangi dosya oldugunu goremez)
	 *   - kural uretmiyor
	 *   - ama 10 dakikada 43.641 kayit uretip 10 MB dosyayi dolduruyor
	 *
	 * Yani saf gurultu + disk maliyeti. Uretilmiyor.
	 *
	 * DENY kayitlari ETKILENMEZ: onlar policy kuralinin kendisidir
	 * (ornegin subject=md5sum), yola ihtiyaci yoktur ve operator
	 * icin anlamlidir.
	 *
	 * Yola ihtiyaci olan butun durumlar zaten file_open ve
	 * bprm_check_security kancalarinda, yol COZULMUŞ halde kaydedilir.
	 */
	return 0;
}
