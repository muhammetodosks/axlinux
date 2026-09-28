/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/socket_connect kancası
 * disarı baglanti kontrolu.
 */


SEC("lsm/socket_connect")
int BPF_PROG(ax_socket_connect, struct socket *sock,
	     struct sockaddr *address, int addrlen, int ret)
{
	struct policy_key *key = ax_key();
	struct audit_event *event = ax_event();
	struct policy_value *val;
	__u32 mode;

	mode = ax_mode();
	if (mode == MODE_DISABLED)
		return 0;

	if (!sock || !address || !key || !event)
		return 0;

	__builtin_memset(key, 0, sizeof(*key));
	__builtin_memset(event, 0, sizeof(*event));

	ax_get_comm(key->comm);
	key->action = ACTION_NET_CONNECT;

	/* Unix socket yolu sockaddr_un icinde. Dogrudan erisim
	 * "access beyond struct sockaddr" ile verifier'da reddedilir
	 * (struct sockaddr yalnizca 16 bayt). bpf_core_read CO-RE ile
	 * sinir guvenli okuma yapar ve hedef cekirdekteki gercek
	 * sockaddr_un duzenine uyum saglar. */
	if (address->sa_family == AF_UNIX) {
		const struct sockaddr_un *un = (const void *)address;

		if (addrlen > (int)sizeof(*un))
			bpf_core_read(key->path, sizeof(key->path) - 1,
				      &un->sun_path);
	}
	/* IP adresi icin kural Go tarafinda port ile birlikte map'e yazilir;
	 * burada path bos birakilir. */

	val = ax_lookup(key);
	if (!val || val->effect != EFFECT_DENY)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, key->path, sizeof(event->path));
	event->action = ACTION_NET_CONNECT;
	event->effect = EFFECT_DENY;
	event->rule_id = val->rule_id;
	event->hook_type = HOOK_SOCKET_CONNECT;

	if (mode == MODE_ENFORCING) {
		event->decision = DECISION_DENIED;
		ax_audit(ctx, event);
		return -EPERM;
	}

	event->decision = DECISION_ALLOWED;
	ax_audit(ctx, event);
	return 0;
}
