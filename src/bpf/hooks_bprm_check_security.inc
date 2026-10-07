/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/bprm_check_security kancası
 * execve kontrolu.
 */


SEC("lsm/bprm_check_security")
int BPF_PROG(ax_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct audit_event *event = ax_event();
	struct policy_value *val;
	__u32 mode;
	struct file *file;

	/* Koruma kontrolu icin PID; ayrica event->pid de
	 * bunu kullanir (bpf_get_current_pid_tgid bir kez). */
	__u32 cur_pid = bpf_get_current_pid_tgid() >> 32;

	mode = ax_mode();
	if (mode == MODE_DISABLED)
		return 0;

	if (!bprm || !event)
		return 0;

	/* vmlinux.h include edildigi icin dogrudan erisim CO-RE relocation
	 * uretir; BPF_CORE_READ yerine bu tercih edildi. */
	file = bprm->file;
	if (!file)
		return 0;

	ax_event_clear(event);

	/*
	 * Iki ayri kural grubu denetlenir ve DENY olan varsa her zaman
	 * engellenir:
	 *
	 *   1) process.exec  -> "nginx hicbir sey calistiramaz"
	 *   2) file.execute  -> "nginx /bin/bash'i calistiramaz"
	 *
	 * Once surec kuralina bakilir, yol kurali yalnizca surec kurali
	 * isabet etmezse sorgulanir. Ikisine de bakildigi icin biri
	 * yazilirken digeri atlanip bypass edilemez.
	 */
	/* Iki kural grubu iki AYRI per-CPU anahtarda hazirlanir ve
	 * tek ax_lookup2 cagrisiyla birlikte sorgulanir. Ayri iki
	 * ax_lookup cagrisi verifier'da instruction patlamasina
	 * yol actigi icin birlesiktirilir. */
	char target[AX_NAME_MAX];
	int ti;
	struct policy_key *pkey = ax_key(0);   /* yol kurali */
	struct path_buf *pb = ax_pathbuf();   /* + surec kurali anahtari */
	struct policy_key *skey;

	if (!pkey || !pb)
		return 0;
	skey = &pb->skey;

	/* 1) yol bazli file.execute
	 *
	 * Once memset, sonra koruma kontrolu: memset comm alanini
	 * sildigi icin sira bu olmelidir. Bu kanca exec'i denetledigi
	 * icin koruma olmadan "bash /bin/echo calistiramaz" turunden
	 * bir kural, bash'in kendi oturumunu kilitleyerek kullaniciyi
	 * sistem disi birakir (bkz. ax_protected). */
	__builtin_memset(pkey, 0, sizeof(*pkey));
	ax_get_comm(pkey->comm);
	pkey->action = ACTION_FILE_EXEC;
	ax_fill_path((struct path *)&file->f_path, pkey);
	ax_fill_audit_path((struct path *)&file->f_path, event);

	/* Hedef binary'nin adi = yolun EN DERIN dolu bileseni.
	 * (Slotlar 7'den 0'a dogru doldurulur.)
	 *
	 * KRITIK: bprm_check_security aninda
	 * bpf_get_current_comm() YENI BINARI DEGIL, CALISAN
	 * SURECI verir; execve henuz gerceklesmemistir. Onceki
	 * kod hedef yerine bpf_get_comm() kullanip surec kuralini
	 * "curl" yerine "sudo"/"bash" ile sorguluyordu, bu yuzden
	 * hicbir zaman eslesmiyordu. */
	/* Slotlar Go ile ORTAK bicimde, BASI "/" olacak sekilde
	 * yazilir (ax_fill_path: key->path[b][0] = '/'). Go tarafi bu
	 * bicimi cozup "/usr/bin/sleep" olusturur.
	 *
	 * OZELDE hedef ad burada ALINIRKEN bastaki '/' ATLANMALI.
	 * Atlanmazsa target "/sleep" olur; politika anahtari ise
	 * "sleep" bekler, anahtarlar kesismez ve kural HIC
	 * UYGULANMAZ. Process.exec ve file.execute bu yuzden hic
	 * calismiyordu.
	 */
	__builtin_memset(target, 0, sizeof(target));
#pragma unroll
	for (ti = 0; ti < AX_PATH_DEPTH; ti++) {
		if (pkey->path[ti][0] != '\0') {
			/* Hedef ad 16 bayta kadar alinir ve NULL ile
			 * sonlandirilir. Dallanmadan iki 8 baytlik
			 * tasima kullanilir:
			 *
			 *   - veriye bagli `break` iceren dongu
			 *     clang tarafindan ACILAMIYORDU
			 *     ("loop not unrolled") ve her exec'te
			 *     dongu maliyeti olusturuyordu.
			 *   - comm alani zaten 16 bayt; daha uzun adlar
			 *     kirpilir ve dogru sekilde sonlandirilir.
			 *
			 * Slotun BASINDAKI '/' atlanir: slotlar Go ile
			 * ortak bicimde "/ad" olarak yazilir.
			 */
			__u32 off = (pkey->path[ti][0] == '/') ? 1 : 0;
			__u64 lo = 0, hi = 0;

			__builtin_memcpy(&lo, pkey->path[ti] + off, 8);
			__builtin_memcpy(&hi, pkey->path[ti] + off + 8, 8);
			__builtin_memcpy(target, &lo, 8);
			__builtin_memcpy(target + 8, &hi, 8);
			target[15] = '\0';
		}
	}
	/* Yol cozulemediyse ebeveyne dus: "bash calistirilamaz"
	 * turu bir kural yine de yakalansin. */
	if (target[0] == '\0')
		ax_get_comm(target);

	/* Koruma EBVEYNDE DEGIL HEDEFTE kontrol edilir.
	 *
	 * Once pkey->comm uzerinde kontrol ediliyordu; "bash",
	 * "sudo", "systemd" korumali oldugu icin kanca HER
	 * ZAMAN erkenden donuyor, tum process.exec kurallari
	 * etkisiz kaliyordu.
	 *
	 * deep_verify'daki test de yanlis yolla gecidi: python3
	 * calistiriliyor, blok HIC olmuyor, python3 kendi koduyla
	 * exit(1) donuyordu; test "1 bekliyordu, 1 aldi" deyip
	 * gecti.
	 *
	 * Dogru: kilitleme riski hedef BINARY yazginca dogar
	 * ("bash'i yasakla"). Ebeveynin korumali olmasi hedefin
	 * yasaklanmasina engel OLMAMALIDIR. */
	if (ax_protected(target))
		return 0;

	/* 2) surec bazli process.exec (yol bos) */
	__builtin_memset(skey, 0, sizeof(*skey));
	ax_clear_path(skey);
	skey->action = ACTION_PROCESS_EXEC;
	__builtin_memcpy(skey->comm, target, sizeof(skey->comm));

	/* Audit alanlari map aramasindan ONCE doldurulur:
	 * bpf_map_lookup_elem cagrisi sonrasi verifier pkey
	 * pointer'ini "unbounded" isaretliyor ve yazma reddediliyor. */
	event = ax_event();
	if (!event)
		return 0;
	__builtin_memcpy(event->comm, target, sizeof(event->comm));
	__builtin_memcpy(event->path, pkey->path, sizeof(event->path));
	event->pid = cur_pid;
	event->action = pkey->action;
	event->effect = EFFECT_DENY;
	event->hook_type = HOOK_BPRM_CHECK_SECURITY;

		val = ax_lookup2(pkey, skey);
		if (!val || val->effect != EFFECT_DENY) {
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
