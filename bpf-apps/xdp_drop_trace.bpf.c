/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

SEC("fentry/xdp_prog_drop")
int BPF_PROG(trace_on_entry, struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	int pkt_sz = data_end - data;

	bpf_printk("[fentry] packet size: %d", pkt_sz);

	return 0;
}

SEC("fexit/xdp_prog_drop")
int BPF_PROG(trace_on_exit, struct xdp_md *xdp, int ret)
{
	bpf_printk("[fexit] ret: %d", ret);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
