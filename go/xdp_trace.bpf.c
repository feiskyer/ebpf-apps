/* SPDX-License-Identifier: GPL-2.0 */
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_md *xdp)
{
	void *data = (void *)(long)BPF_CORE_READ(xdp, data);
	void *data_end = (void *)(long)BPF_CORE_READ(xdp, data_end);

	struct ethhdr *eth = (struct ethhdr *)data;
	__be16 proto = BPF_CORE_READ(eth, h_proto);
	bpf_printk("[fentry/xdp] packet proto %d", proto);
	return 0;
}

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp, struct xdp_md *xdp, int ret)
{
	bpf_printk("[fexit/xdp] ret: %d", ret);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
