/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/inode_permission kancası
 * inode erisim izni kontrolu (okuma / yazma / calistirma).
 */


/* MAY_READ=4, MAY_WRITE=2, MAY_EXEC=1 */
static __always_inline __u32 mask_to_action(int mask)
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
	struct policy_key *key = ax_key();
	struct audit_event *event = ax_event();
	struct policy_value *val;
	__u32 mode;
	__u32 action;

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
	key->path[0] = '\0';

	val = ax_lookup(key);
	if (!val || val->effect != EFFECT_DENY)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	event->action = action;
	event->effect = EFFECT_DENY;
	event->rule_id = val->rule_id;
	event->hook_type = HOOK_INODE_PERMISSION;

	if (mode == MODE_ENFORCING) {
		event->decision = DECISION_DENIED;
		ax_audit(ctx, event);
		return -EPERM;
	}

	event->decision = DECISION_ALLOWED;
	ax_audit(ctx, event);
	return 0;
}
