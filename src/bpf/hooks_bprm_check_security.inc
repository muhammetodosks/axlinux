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

	__builtin_memset(event, 0, sizeof(*event));

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
	if (ax_protected(pkey->comm))
		return 0;
	pkey->action = ACTION_FILE_EXEC;
	ax_fill_path((struct path *)&file->f_path, pkey);

	/* 2) surec bazli process.exec (yol bos) */
	__builtin_memset(skey, 0, sizeof(*skey));
	ax_get_comm(skey->comm);
	ax_clear_path(skey);
	skey->action = ACTION_PROCESS_EXEC;

	/* Audit alanlari map aramasindan ONCE doldurulur:
	 * bpf_map_lookup_elem cagrisi sonrasi verifier pkey
	 * pointer'ini "unbounded" isaretliyor ve yazma reddediliyor. */
	event = ax_event();
	if (!event)
		return 0;
	__u32 eff_action = pkey->action;
	__builtin_memcpy(event->comm, pkey->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, pkey->path, sizeof(event->path));
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->action = eff_action;
	event->effect = EFFECT_DENY;
	event->hook_type = HOOK_BPRM_CHECK_SECURITY;

	val = ax_lookup2(pkey, skey);
	if (!val || val->effect != EFFECT_DENY)
		return 0;
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
