/* SPDX-License-Identifier: GPL-2.0
 * AXlinux - ortak eBPF LSM basligi
 *
 * Yapilar vmlinux.h (BTF) uzerinden gelir. Elle struct yazilmaz.
 */
#ifndef __AXBPF_H
#define __AXBPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef EPERM
#define EPERM 1
#endif

/* Aksiyon tipleri - Go tarafi ile birebir ayni numaralandirma */
#define ACTION_FILE_READ     1
#define ACTION_FILE_WRITE    2
#define ACTION_FILE_EXEC     3
#define ACTION_FILE_DELETE   4
#define ACTION_FILE_CREATE   5
#define ACTION_NET_CONNECT   6
#define ACTION_NET_BIND      7
#define ACTION_NET_ACCEPT    8
#define ACTION_PROCESS_EXEC  9

/* LSM kanca tipleri */
#define HOOK_FILE_OPEN            1
#define HOOK_INODE_PERMISSION     2
#define HOOK_BPRM_CHECK_SECURITY  3
#define HOOK_SOCKET_CONNECT       4
#define HOOK_SOCKET_BIND          5

/* Modlar */
#define MODE_DISABLED    0
#define MODE_PERMISSIVE  1
#define MODE_ENFORCING   2

#define EFFECT_DENY      0
#define EFFECT_ALLOW     1

#define DECISION_ALLOWED 0
#define DECISION_DENIED  1

#define MAX_PATH_LEN     256

/* vmlinux.h bu degerleri enum olarak saglamaz, sayisal olarak veriyoruz */
#ifndef AF_UNIX
#define AF_UNIX  1
#endif
#ifndef AF_INET
#define AF_INET  2
#endif

/* Anahtar: comm + path + action */
struct policy_key {
	char comm[16];
	char path[MAX_PATH_LEN];
	__u32 action;
};

/* Deger: hangi kural ve ne etki */
struct policy_value {
	__u32 rule_id;
	__u32 effect;
};

/* Audit olayi (perf buffer) */
struct audit_event {
	__u64 timestamp;
	__u32 pid;
	char comm[16];
	char path[MAX_PATH_LEN];
	__u32 action;
	__u32 effect;
	__u32 decision;
	__u32 rule_id;
	__u32 hook_type;
};

/* Izin verilen kurallar */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct policy_key);
	__type(value, struct policy_value);
} allow_map SEC(".maps");

/* Yasaklanan kurallar */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct policy_key);
	__type(value, struct policy_value);
} deny_map SEC(".maps");

/* Audit perf buffer */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} audit_buffer SEC(".maps");

/* Aktif mod (0=disabled, 1=permissive, 2=enforcing) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} mode_map SEC(".maps");

/* Stack limiti (512B) policy_key + audit_event toplamini asamaz.
 * Bu yuzden calisma zamani tamponlari per-CPU map icinde tutulur. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_key);
} key_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct audit_event);
} event_scratch SEC(".maps");

/* Yardimcilar */

static __always_inline struct policy_key *ax_key(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&key_scratch, &zero);
}

static __always_inline struct audit_event *ax_event(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&event_scratch, &zero);
}

static __always_inline void ax_get_comm(char *comm)
{
	bpf_get_current_comm(comm, 16);
}

static __always_inline __u32 ax_mode(void)
{
	__u32 key = 0;
	__u32 *mode = bpf_map_lookup_elem(&mode_map, &key);

	if (!mode)
		return MODE_ENFORCING;
	return *mode;
}

/* deny_map once bakilir, sonra allow_map. Bulunamazsa NULL. */
static __always_inline struct policy_value *ax_lookup(struct policy_key *key)
{
	struct policy_value *val;

	val = bpf_map_lookup_elem(&deny_map, key);
	if (val)
		return val;

	val = bpf_map_lookup_elem(&allow_map, key);
	if (val)
		return val;

	return NULL;
}

/* Audit olayini perf buffer'a yazar.
 *
 * bpf_perf_event_output(ctx, map, flags, data, size) imzasi ilk
 * argumani program ctx'si ister. ctx olamayan bir yardimciya
 * gecirildiginde verifier "R1 type=map_value expected=ctx" ile
 * programi reddeder; bu yuzden her kanca ctx'yi gecmelidir.
 */
static __always_inline void ax_audit(void *ctx, struct audit_event *event)
{
	event->timestamp = bpf_ktime_get_ns();
	bpf_perf_event_output(ctx, &audit_buffer, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));
}

#endif /* __AXBPF_H */
