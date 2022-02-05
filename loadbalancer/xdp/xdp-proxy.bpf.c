#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp-proxy.h"

/*
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, struct endpoints);
	 __uint(max_entries, 1024);
} services SEC(".maps");
*/

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++)
	{
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph)
{
	iph->check = 0;
	unsigned long long csum =
		bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
	return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_proxy(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	/* abort on illegal packets */
	if (data + sizeof(struct ethhdr) > data_end)
	{
		return XDP_ABORTED;
	}

	/* do nothing for non-IP packets */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
	{
		return XDP_PASS;
	}

	struct iphdr *iph = data + sizeof(struct ethhdr);
	/* abort on illegal packets */
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	{
		return XDP_ABORTED;
	}

	/* do nothing for non-TCP packets */
	if (iph->protocol != IPPROTO_TCP)
	{
		return XDP_PASS;
	}

	// __be32 svc1_key = SVC1_KEY;
	// struct endpoints *ep = bpf_map_lookup_elem(&services, &svc1_key);
	// if (!ep) {
	// 	return XDP_PASS;
	// }
	// bpf_printk("Client IP: %ld", ep->client);
	// bpf_printk("Endpoint IPs: %ld, %ld", ep->ep1, ep->ep2);
	// bpf_printk("New TCP packet %ld => %ld\n", iph->saddr, iph->daddr);

	/*
		ep1:    172.17.0.2 => 0x20011ac
		ep2:    172.17.0.3 => 0x30011ac
		client: 172.17.0.4 => 0x40011ac
		vip:    172.17.0.5 => 0x50011ac
	 */
	if (iph->saddr == 0x40011ac /*ep- > client*/)
	{
		iph->daddr = 0x20011ac /*ep- > ep1*/;
		eth->h_dest[5] = 2;
		if (bpf_get_prandom_u32() % 2 == 0)
		{
			iph->daddr = 0x30011ac /*ep- > ep2*/;
			eth->h_dest[5] = 3;
		}
	}
	else if (iph->saddr == 0x20011ac || iph->saddr == 0x30011ac)
	{
		iph->daddr = 0x40011ac /*ep- > client*/;
		eth->h_dest[5] = 4;
	} else {
		return XDP_PASS;
	}

	iph->saddr = 0x50011ac /*ep- > vip*/;
	eth->h_source[5] = 5;

	iph->check = iph_csum(iph);
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
