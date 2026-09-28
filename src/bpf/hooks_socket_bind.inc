/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/socket_bind kancası
 * port dinleme kontrolu.
 */


SEC("lsm/socket_bind")
int BPF_PROG(ax_socket_bind, struct socket *sock,
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
	key->action = ACTION_NET_BIND;

	/* Port anahtara "p:<host-order port>" bicimiyle yazilir.
	 * Go tarafi ayni bicimi uretir. */
	if (address->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const void *)address;
		__u16 hport = bpf_ntohs(in->sin_port);

		if (addrlen >= (int)sizeof(*in)) {
			key->path[0] = 'p';
			key->path[1] = ':';
			__builtin_memcpy(key->path + 2, &hport, sizeof(hport));
		}
	}

	val = ax_lookup(key);
	if (!val || val->effect != EFFECT_DENY)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, key->path, sizeof(event->path));
	event->action = ACTION_NET_BIND;
	event->effect = EFFECT_DENY;
	event->rule_id = val->rule_id;
	event->hook_type = HOOK_SOCKET_BIND;

	if (mode == MODE_ENFORCING) {
		event->decision = DECISION_DENIED;
		ax_audit(ctx, event);
		return -EPERM;
	}

	event->decision = DECISION_ALLOWED;
	ax_audit(ctx, event);
	return 0;
}
