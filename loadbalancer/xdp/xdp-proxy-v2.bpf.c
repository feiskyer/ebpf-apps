#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp-proxy-v2.h"

/* define a hashmap for userspace to update service endpoints */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, struct endpoints);
	__uint(max_entries, 1024);
} services SEC(".maps");

/* Refer https://github.com/facebookincubator/katran/blob/main/katran/lib/bpf/csum_helpers.h#L30 */
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

static __always_inline __u16 ipv4_csum(struct iphdr *iph)
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

	__be32 svc1_key = SVC1_KEY;
	struct endpoints *ep = bpf_map_lookup_elem(&services, &svc1_key);
	if (!ep)
	{
		return XDP_PASS;
	}
	// bpf_printk("Client IP: %ld", ep->client);
	// bpf_printk("Endpoint IPs: %ld, %ld", ep->ep1, ep->ep2);
	// bpf_printk("New TCP packet %ld => %ld\n", iph->saddr, iph->daddr);

	if (iph->saddr == ep->client)
	{
		iph->daddr = ep->ep1;
		memcpy(eth->h_dest, ep->ep1_mac, ETH_ALEN);

		/* simulate random selection of two endpoints */
		if ((bpf_ktime_get_ns() & 0x1) == 0x1)
		{
			iph->daddr = ep->ep2;
			memcpy(eth->h_dest, ep->ep2_mac, ETH_ALEN);
		}
	}
	else
	{
		iph->daddr = ep->client;
		memcpy(eth->h_dest, ep->client_mac, ETH_ALEN);
	}

	/* packet source is always LB itself */
	iph->saddr = ep->vip;
	memcpy(eth->h_source, ep->vip_mac, ETH_ALEN);

	/* recalculate IP checksum */
	iph->check = ipv4_csum(iph);

	/* send packet back to network stack */
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
