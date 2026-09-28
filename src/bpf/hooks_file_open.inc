/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/file_open kancası
 * Dosya acma kontrolu.
 */


SEC("lsm/file_open")
int BPF_PROG(ax_file_open, struct file *file, int ret)
{
	struct policy_key *key = ax_key();
	struct audit_event *event = ax_event();
	struct policy_value *val;
	__u32 mode;

	mode = ax_mode();
	if (mode == MODE_DISABLED)
		return 0;

	if (!file || !key || !event)
		return 0;

	__builtin_memset(key, 0, sizeof(*key));
	__builtin_memset(event, 0, sizeof(*event));

	ax_get_comm(key->comm);
	key->action = ACTION_FILE_READ;

	/* bpf_d_path imzasi const olmayan struct path alir. Alanin
	 * gercek adresini kullaniriz: stack'a kopyalamak (struct path p)
	 * verifier'a fp (stack) isaretci verir ve
	 * "R1 type=fp expected=ptr_, trusted_ptr_" ile reddedilir.
	 * const yalnizca derleyici uyarisi icin cast ile gecilir; alan
	 * zaten guvenilir (trusted) bir kernel isaretçisidir. */
	struct path *p = (struct path *)&file->f_path;

	/* Root mount ise yol "/" dir, d_path gereksiz */
	if (p->dentry != p->mnt->mnt_root)
		bpf_d_path(p, key->path, sizeof(key->path));
	else
		key->path[0] = '/';

	val = ax_lookup(key);
	if (!val || val->effect != EFFECT_DENY)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, key->path, sizeof(event->path));
	event->action = ACTION_FILE_READ;
	event->effect = EFFECT_DENY;
	event->rule_id = val->rule_id;
	event->hook_type = HOOK_FILE_OPEN;

	if (mode == MODE_ENFORCING) {
		event->decision = DECISION_DENIED;
		ax_audit(ctx, event);
		return -EPERM;
	}

	event->decision = DECISION_ALLOWED;
	ax_audit(ctx, event);
	return 0;
}
