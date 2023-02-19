#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//#include <linux/if_ether.h>
#define ETH_P_IP 0x0800

//#include <linux/pkt_cls.h>
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(value, u16);
	__type(key, u32);
} ports SEC(".maps");

static bool drop_port(__be16 port)
{
	u16 hport = bpf_ntohs(port);
	u32 i = 0;
	for (i = 0; i < 10; i++)
	{
		u32 key = i;
		u16 *drop_port = bpf_map_lookup_elem(&ports, &key);
		if (drop_port && hport == *drop_port)
		{
			return true;
		}
	}

	return false;
}

SEC("tc")
int handle_tc(struct __sk_buff *skb)
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

	// bpf_printk("Got TCP connection with ports: %d -> %d", bpf_htons(tcp->source), bpf_htons(tcp->dest));

	/* drop tcp packets */
	if (drop_port(tcp->dest) || drop_port(tcp->source))
	{
		if (skb->ingress_ifindex) {
			bpf_printk("Dropping ingress packets to %ld:%d\n", iph->daddr,
					   bpf_htons(tcp->dest));
		} else {
			bpf_printk("Dropping egress packets to %ld:%d\n", iph->daddr,
					   bpf_htons(tcp->dest));
		}

		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
