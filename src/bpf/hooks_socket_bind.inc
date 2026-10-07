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

	/* Koruma kontrolu icin PID; ayrica event->pid de
	 * bunu kullanir (bpf_get_current_pid_tgid bir kez). */
	__u32 cur_pid = bpf_get_current_pid_tgid() >> 32;

	mode = ax_mode();
	if (mode == MODE_DISABLED)
		return 0;

	if (!sock || !address || !key || !event)
		return 0;

	__builtin_memset(key, 0, sizeof(*key));
	ax_event_clear(event);

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

	val = ax_lookup_wild(key);
	int denied = val && val->effect == EFFECT_DENY;

	event->pid = cur_pid;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, key->path, sizeof(event->path));
	event->action = ACTION_NET_BIND;
	event->effect = denied ? EFFECT_DENY : EFFECT_ALLOW;
	event->rule_id = denied ? val->rule_id : 0;
	event->hook_type = HOOK_SOCKET_BIND;

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
