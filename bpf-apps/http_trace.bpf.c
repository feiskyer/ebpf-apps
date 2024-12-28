/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "http_trace.h"

#define ETH_HLEN 14
#define ETH_P_IP 0x0800		/* Internet Protocol packet     */
#define IP_MF 0x2000		/* More Fragments */
#define IP_OFFSET 0x1FFF	/* Mask for fragmenting bits */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb)
{
	__u16 frag_off;
	bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, frag_off),
			   &frag_off, sizeof(frag_off));
	frag_off = bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int http_trace(struct __sk_buff *skb)
{
	struct event_t *event;
	__u8 ip_proto;
	__u16 h_proto;

	// 只跟踪 IP 协议的数据包
	bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, 2);
	if (h_proto != bpf_htons(ETH_P_IP)) {
		return 0;
	}

	// 如果是分片包则不跟踪
	if (ip_is_fragment(skb)) {
		return 0;
	}

	// 只跟踪 TCP 协议的数据包
	bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
			   &ip_proto, 1);
	if (ip_proto != IPPROTO_TCP) {
		return 0;
	}

	// 计算IP头部长度（ihl单位为4字节，所以需要乘以4）
	struct iphdr iph;
	bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
	__u32 ip_total_length = iph.tot_len;
	__u32 iph_len = iph.ihl;
	iph_len = iph_len << 2;

	// 根据TCP数据偏移（doff）计算TCP头部长度（doff单位为4字节，所以需要乘以4）
	struct tcphdr tcph;
	bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(iph), &tcph, sizeof(tcph));
	__u32 tcp_hlen = tcph.doff;
	tcp_hlen = tcp_hlen << 2;

	// 只跟踪 TCP 80 端口的数据包
	if (tcph.source != bpf_htons(80) && tcph.dest != bpf_htons(80)) {
		return 0;
	}

	// 计算HTTP payload的偏移和长度
	__u32 payload_offset = ETH_HLEN + iph_len + tcp_hlen;
	__u32 payload_length = bpf_ntohs(ip_total_length) - iph_len - tcp_hlen;
	// HTTP 报文最短为7个字节
	if (payload_length < 7) {
		return 0;
	}

	// 只跟踪 GET、POST、PUT、DELETE 方法的数据包
	// HTTP 开头的数据包是服务器端的响应
	char start_buffer[7] = { };
	bpf_skb_load_bytes(skb, payload_offset, start_buffer, 7);
	if (bpf_strncmp(start_buffer, 3, "GET") != 0 &&
	    bpf_strncmp(start_buffer, 4, "POST") != 0 &&
	    bpf_strncmp(start_buffer, 3, "PUT") != 0 &&
	    bpf_strncmp(start_buffer, 6, "DELETE") != 0 &&
	    bpf_strncmp(start_buffer, 4, "HTTP") != 0) {
		return 0;
	}

	// 读取HTTP信息并将其提交到环形缓冲区
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	event->sport = bpf_ntohs(tcph.source);
	event->dport = bpf_ntohs(tcph.dest);
	event->payload_length = payload_length;
	bpf_skb_load_bytes(skb, payload_offset, event->payload, sizeof(event->payload));
	bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
			   &event->saddr, 4);
	bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
			   &event->daddr, 4);
	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
