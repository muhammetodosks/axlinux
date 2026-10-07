/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/file_open kancası
 * Dosya acma kontrolu.
 *
 * Duzenleme notu: event ve key pointer'lari bprm_check_security
 * ile AYNI sirada alinir (event once, key sonra). Farkli sira
 * verifier'in register tahsisini degistirip key pointer'ini
 * "unbounded" isaretlemeye yol aciyordu.
 */

/* file->f_mode icindeki erisim baytlari (include/linux/fs.h):
 *   FMODE_READ  0x1  okunuyor
 *   FMODE_WRITE 0x2  yaziliyor
 *   FMODE_EXEC  0x4  calistiriliyor
 *
 * FMODE_EXEC burada KULLANILMAZ: file_open ile exec birbirinden
 * bagimsizdir, bir calistirilabilir dosya once file_open'dan gecer
 * (okunuyor) sonra bprm_check_security'de exec olarak denetlenir.
 * Yalnizca FMODE_EXEC olan bir aciilis normalde olmaz; yine de
 * ACTION_FILE_EXEC uretilirse bprm ile ayni yol icin iki farkli
 * kanca ayni karari vermeye zorlanir. Tek kaynak bprm'dir. */
#define AX_FMODE_READ  0x1
#define AX_FMODE_WRITE 0x2

/* file_open kancasinda gercekten hangi islem yapildigini f_mode'den
 * cikarir.
 *
 * ONCE SABIT ACTION_FILE_READ YAZILIYORDU. Bu, yol bazli
 * file.write / file.delete / file.execute kurallarinin HICBIR
 * zaman tutmamasi demekti: kullanici "/etc/shadow yazilamaz" yaziyor,
 * kural map'e giriyor, daemon "1 kural yuklendi" diyor, ama
 * hicbir sey engellenmiyor. inode_permission yol cozumlemediigi
 * icin yol bazli yazma kurallarinin baska hicbir kanacasi da yok.
 *
 * Oncelik sirasi: yazma > okuma. Tek bir aciilis "hem okuma hem
 * yazma" olabilecegi icin (O_RDWR) daha kisitlayici olan once
 * denenir. Sadece yazma icin ACTION_FILE_WRITE uretilir, boylece
 * "okunabilir ama yazilamaz" gibi kurallar dogru calisir. */
static __always_inline __u32 ax_open_action(int fmode)
{
	if (fmode & AX_FMODE_WRITE)
		return ACTION_FILE_WRITE;
	if (fmode & AX_FMODE_READ)
		return ACTION_FILE_READ;
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(ax_file_open, struct file *file, int ret)
{
	struct audit_event *event = ax_event();
	struct policy_value *val;
	__u32 mode;
	__u32 action;

	/* Koruma kontrolu icin PID; ayrica event->pid de
	 * bunu kullanir (bpf_get_current_pid_tgid bir kez). */
	__u32 cur_pid = bpf_get_current_pid_tgid() >> 32;

	mode = ax_mode();
	if (mode == MODE_DISABLED)
		return 0;

	/* file NULL olabilir: LSM kancalari erisim reddedilmis
	 * dosyalarda da cagrilir. NULL kontrolu olmadan
	 * &file->f_path okumasi cokmem degil, yanlis deger uretir. */
	if (!file || !event)
		return 0;

	ax_event_clear(event);

	struct policy_key *key = ax_key(0);
	if (!key)
		return 0;

	action = ax_open_action(BPF_CORE_READ(file, f_mode));
	if (!action)
		return 0;

	__builtin_memset(key, 0, sizeof(*key));
	ax_get_comm(key->comm);
	key->action = action;

	/* Kritik sistem surecleri hicbir kurala tabi degildir
	 * (bkz. ax_protected). Aksi halde policy, oturumu acan
	 * sureci kilitleyerek sistemi kullanilamaz hale getirir. */
	if (ax_protected(key->comm))
		return 0;

	/* bpf_d_path yerine kendi cozumleyicimiz; bkz. axbpf.h */
	ax_fill_path((struct path *)&file->f_path, key);
	/* Audit yolu policy anahtarindan genistir: 31 karakterden
	 * uzun dosya adi ve 8'den derin dizin de kayda tam yazilir.
	 * Anahtar temsil edemediginde kayit yine de BOS DEGILDIR. */
	ax_fill_audit_path((struct path *)&file->f_path, event);

	/* Audit alanlari map aramasindan ONCE doldurulur:
	 * bpf_map_lookup_elem cagrisi sonrasi verifier key/event
	 * pointer'larini "unbounded" isaretliyor ve yazma
	 * reddediliyor. */
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, key->path, sizeof(event->path));
	event->pid = cur_pid;
	event->action = action;
	event->effect = EFFECT_DENY;
	event->hook_type = HOOK_FILE_OPEN;

		/* ax_decide: tam eslesme + dizin (onek) kurallari.
		 * Deny onekleri once taranir; "deny her zaman once"
		 * sozunu onekler icin de tutar. */
		val = ax_decide(key, 1);
		if (!val || val->effect != EFFECT_DENY) {
	/* Ogrenme gozlemi.
	 *
	 * Buraya kadar yalnizca DENY kurali eslesen operasyonlar
	 * olay uretiyordu. Ogrenme modunun amaci ise tam tersidir:
	 * "normalde ne yapiyorsun" gozlemi. Normal isler tanim
	 * geregi IZIN VERILEN operasyonlardir, yani hicbiri olay
	 * uretmiyordu. Sonuc: ogrenme modu AÇILSA BILE sifir
	 * gozlem toplaniyordu; kullaniciya "3 gun kayit tutulacak"
	 * yazilip hicbir sey toplanmiyordu.
	 *
	 * Burada izin verilen operasyon bir gozleme donusur.
	 * Yalnizca ogrenme ACIKKEN: her izinli dosya okumasini
	 * surekli audit etmek sistemde gereksiz yuk olusturur.
	 */
		if (ax_learning()) {
			event->effect = EFFECT_ALLOW;
			event->rule_id = 0;
			event->decision = DECISION_ALLOWED;
			ax_audit(ctx, event);
		}
		return 0;
	}
	event->rule_id = val->rule_id;

	if (mode == MODE_ENFORCING) {
		event->decision = DECISION_DENIED;
		ax_audit(ctx, event);
		return -EPERM;
	}

	event->decision = DECISION_ALLOWED;
	ax_audit(ctx, event);
	return 0;
}
