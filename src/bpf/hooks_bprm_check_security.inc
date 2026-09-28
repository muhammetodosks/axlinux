/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/bprm_check_security kancası
 * execve kontrolu.
 */


SEC("lsm/bprm_check_security")
int BPF_PROG(ax_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct policy_key *key = ax_key();
	struct audit_event *event = ax_event();
	struct policy_value *val;
	__u32 mode;
	struct file *file;

	mode = ax_mode();
	if (mode == MODE_DISABLED)
		return 0;

	if (!bprm || !key || !event)
		return 0;

	/* vmlinux.h include edildigi icin dogrudan erisim CO-RE relocation
	 * uretir; BPF_CORE_READ yerine bu tercih edildi. */
	file = bprm->file;
	if (!file)
		return 0;

	__builtin_memset(key, 0, sizeof(*key));
	__builtin_memset(event, 0, sizeof(*event));

	ax_get_comm(key->comm);

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
	struct policy_value *procVal = NULL;
	struct policy_value *pathVal = NULL;

	/* 1) surec bazli process.exec (yol bos) */
	key->path[0] = '\0';
	key->action = ACTION_PROCESS_EXEC;
	procVal = ax_lookup(key);

	/* 2) yol bazli file.execute
	 *
	 * bpf_d_path stack kopyasi kabul etmez (verifier guvenilir
	 * isaretci ister), bu yuzden alanin gercek adresi kullanilir. */
	struct path *p = (struct path *)&file->f_path;

	key->action = ACTION_FILE_EXEC;
	if (p->dentry != p->mnt->mnt_root)
		bpf_d_path(p, key->path, sizeof(key->path));
	else
		key->path[0] = '/';
	pathVal = ax_lookup(key);

	val = pathVal;
	if (!val)
		val = procVal;

	if (!val || val->effect != EFFECT_DENY)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, key->path, sizeof(event->path));
	event->action = key->action;
	event->effect = EFFECT_DENY;
	event->rule_id = val->rule_id;
	event->hook_type = HOOK_BPRM_CHECK_SECURITY;

	if (mode == MODE_ENFORCING) {
		event->decision = DECISION_DENIED;
		ax_audit(ctx, event);
		return -EPERM;
	}

	event->decision = DECISION_ALLOWED;
	ax_audit(ctx, event);
	return 0;
}
