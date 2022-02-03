/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("action/egress")
int tc_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) {
		return TC_ACT_OK;	/* continue the kernel network stack */
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return TC_ACT_OK;
	}

	if (iph->protocol != IPPROTO_TCP) {
		return TC_ACT_OK;
	}
	//bpf_printk("Tracing TCP packet %ld => %ld\n", iph->saddr, iph->daddr);

	struct tcphdr *tcp =
	    (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if (tcp + 1 > (struct tcphdr *)data_end) {
		return TC_ACT_OK;
	}
	//bpf_printk("TCP Ports: %d -> %d", bpf_htons(tcp->source), bpf_htons(tcp->dest));

	/* drop tcp 80 packets */
	if (tcp->dest == bpf_htons(80)) {
		bpf_printk("Dropping packets to %ld:%d\n", iph->daddr,
			   bpf_htons(tcp->dest));
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("action/ingress")
int tc_ingress(struct __sk_buff *sk)
{
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
