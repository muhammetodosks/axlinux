/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - lsm/socket_connect kancası
 * disarı baglanti kontrolu.
 */


SEC("lsm/socket_connect")
int BPF_PROG(ax_socket_connect, struct socket *sock,
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
	key->action = ACTION_NET_CONNECT;

	/* Kritik sistem surecleri hicbir kurala tabi degildir */
	if (ax_protected(key->comm))
		return 0;

	/* Unix socket yolu sockaddr_un icinde. Dogrudan erisim
	 * "access beyond struct sockaddr" ile verifier'da reddedilir
	 * (struct sockaddr yalnizca 16 bayt). bpf_core_read CO-RE ile
	 * sinir guvenli okuma yapar ve hedef cekirdekteki gercek
	 * sockaddr_un duzenine uyum saglar.
	 *
	 * IP adresinde path BOS BIRAKILIRSA kural hicbir zaman
	 * tutmaz: Go tarafi net.connect kurallarini port ile birlikte
	 * "p:PORT" bicimiyle yaziyor, o yuzden burada da port ayni
	 * sekilde yazilir. */
	if (address->sa_family == AF_UNIX) {
		const struct sockaddr_un *un = (const void *)address;

		if (addrlen > (int)sizeof(*un))
			bpf_core_read(key->path[0], AX_PATH_SLOT - 1,
				      &un->sun_path);
	} else if (address->sa_family == AF_INET) {
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

	event->pid = bpf_get_current_pid_tgid() >> 32;
	__builtin_memcpy(event->comm, key->comm, sizeof(event->comm));
	__builtin_memcpy(event->path, key->path, sizeof(event->path));
	event->action = ACTION_NET_CONNECT;
	event->effect = denied ? EFFECT_DENY : EFFECT_ALLOW;
	event->rule_id = denied ? val->rule_id : 0;
	event->hook_type = HOOK_SOCKET_CONNECT;

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
