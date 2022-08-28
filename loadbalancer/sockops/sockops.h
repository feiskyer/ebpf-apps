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

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(key_size, sizeof(struct sock_key));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} sock_ops_map SEC(".maps");

#endif				/* __SOCK_OPS_H__ */
