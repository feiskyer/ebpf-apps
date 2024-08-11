#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
	Assuming IP and MAC addresses are following:

	client       => 172.17.0.4 (Hex 0x40011ac) => 02:42:ac:11:00:04
	loadbalancer => 172.17.0.5 (Hex 0x50011ac) => 02:42:ac:11:00:05
	endpoint1    => 172.17.0.2 (Hex 0x20011ac) => 02:42:ac:11:00:02
	endpoint2    => 172.17.0.3 (Hex 0x30011ac) => 02:42:ac:11:00:03
*/
#define CLIENT_IP 0x40011ac
#define LOADBALANCER_IP 0x50011ac
#define ENDPOINT1_IP 0x20011ac
#define ENDPOINT2_IP 0x30011ac
#define CLIENT_MAC_SUFFIX 0x04
#define LOADBALANCER_MAC_SUFFIX 0x05
#define ENDPOINT1_MAC_SUFFIX 0x02
#define ENDPOINT2_MAC_SUFFIX 0x03

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

	if (iph->saddr == CLIENT_IP)
	{
		iph->daddr = ENDPOINT1_IP;
		/* Only need to update the last byte */
		eth->h_dest[5] = ENDPOINT1_MAC_SUFFIX;

		/* simulate random selection of two endpoints */
		if ((bpf_ktime_get_ns() & 0x1) == 0x1)
		{
			iph->daddr = ENDPOINT2_IP;
			eth->h_dest[5] = ENDPOINT2_MAC_SUFFIX;
		}
	}
	else
	{
		iph->daddr = CLIENT_IP;
		eth->h_dest[5] = CLIENT_MAC_SUFFIX;
	}

	/* packet source is always LB itself */
	iph->saddr = LOADBALANCER_IP;
	eth->h_source[5] = LOADBALANCER_MAC_SUFFIX;

	/* recalculate IP checksum */
	iph->check = ipv4_csum(iph);

	/* send packet back to network stack */
	return XDP_TX;
}

char _license[] SEC("license") = "Dual BSD/GPL";
