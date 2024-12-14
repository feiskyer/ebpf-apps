/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_drop(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pkt_sz = data_end - data;

	bpf_printk("packet size: %d", pkt_sz);

	struct ethhdr *eth = data;
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return XDP_PASS;
	}

	if (iph->protocol == IPPROTO_ICMP) {
		return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
