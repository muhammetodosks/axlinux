/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/socket_bind kancası
 * port dinleme kontrolu.
 */


SEC("lsm/socket_bind")
int BPF_PROG(ax_socket_bind, struct socket *sock,
	     struct sockaddr *address, int addrlen, int ret)
{
	struct policy_key *key = ax_key(0);
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

	/* Kritik sistem surecleri hicbir kurala tabi degildir */
	if (ax_protected(key->comm))
		return 0;

	/* Port anahtara "p:<host-order port>" bicimiyle yazilir.
	 * Go tarafi ayni bicimi uretir (fmt.Sprintf("p:%d", port)).
	 * Daha once yalnizca AF_INET ele aliniyordu: IPv6 dinleyiciler
	 * (cift yigin baglantilarinda varsayilan) hicbir kurala
	 * tabi olmuyordu, yani "bu surec 8080 dinleyemez" kurali
	 * IPv6'da sessizce gecersizdi. */
	if (address->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const void *)address;
		__u16 hport = bpf_ntohs(in->sin_port);

		if (addrlen >= (int)sizeof(*in))
			ax_set_port(key->path[0], hport);
	} else if (address->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const void *)address;
		__u16 hport = bpf_ntohs(in6->sin6_port);

		if (addrlen >= (int)sizeof(*in6))
			ax_set_port(key->path[0], hport);
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
