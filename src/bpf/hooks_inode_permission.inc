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
	struct policy_key *key = ax_key(0);
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
	ax_clear_path(key);

	/* Kritik sistem surecleri hicbir kurala tabi degildir */
	if (ax_protected(key->comm))
		return 0;

	val = ax_lookup_wild(key);
	int denied = val && val->effect == EFFECT_DENY;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	event->action = action;
	event->effect = denied ? EFFECT_DENY : EFFECT_ALLOW;
	event->rule_id = denied ? val->rule_id : 0;
	event->hook_type = HOOK_INODE_PERMISSION;

	if (!denied) {
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
			event->decision = DECISION_ALLOWED;
			ax_audit(ctx, event);
		}
		return 0;
	}

	if (mode == MODE_ENFORCING) {
		event->decision = DECISION_DENIED;
		ax_audit(ctx, event);
		return -EPERM;
	}

	event->decision = DECISION_ALLOWED;
	ax_audit(ctx, event);
	return 0;
}
