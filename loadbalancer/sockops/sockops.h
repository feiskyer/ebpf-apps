#ifndef __SOCK_OPS_H__
#define __SOCK_OPS_H__

#include <linux/bpf.h>

struct sock_key {
	__u32 sip;
	__u32 dip;
	__u32 sport;
	__u32 dport;
	__u32 family;
};

struct bpf_map_def SEC("maps") sock_ops_map = {
	.type = BPF_MAP_TYPE_SOCKHASH,
	.key_size = sizeof(struct sock_key),
	.value_size = sizeof(int),
	.max_entries = 65535,
	.map_flags = 0,
};

#endif				/* __SOCK_OPS_H__ */
