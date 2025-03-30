/* 导入头文件 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* 常量定义 */
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_SHOT		2

u8 rc_allow = TC_ACT_UNSPEC;
u8 rc_disallow = TC_ACT_SHOT;

/* 定义BPF映射，用于用户空间配置允许的端口号 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(value, u16);
    __type(key, u32);
} allow_ports SEC(".maps");

/* 如果端口号在允许的端口号列表中，则允许该端口 */
static bool allow_port(__be16 port)
{
    u16 hport = bpf_ntohs(port);
    u32 i = 0;
    for (i = 0; i < 10; i++) {
        u32 key = i;
        u16 *allow_port = bpf_map_lookup_elem(&allow_ports, &key);
        if (allow_port && hport == *allow_port) {
            return true;
        }
    }

    return false;
}

/* TC 程序主函数  */
SEC("tc")
int handle_tc(struct __sk_buff *skb)
{
    /* 默认不允许 */
    int rc = rc_disallow;

    /* 定义变量 */
    __be16 dst = 0;
    __be16 src = 0;
    __be16 port = 0;
    __u8 proto = 0;

    /* 检查数据包是否完整 */
    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;
    void *trans_data;
    if (eth + 1 > data_end) {
        return TC_ACT_UNSPEC;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) { // ipv4
        struct iphdr *iph = (struct iphdr *)((void*)eth + sizeof(*eth));
        if ((void*)(iph + 1) > data_end) {
           return TC_ACT_SHOT;
        }

        proto = iph->protocol;
        trans_data = (void*)iph + (iph->ihl * 4);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) { // ipv6
        struct ipv6hdr *ip6h = (struct ipv6hdr *)((void*)eth + sizeof(*eth));
        if ((void*)(ip6h + 1) > data_end) {
           return TC_ACT_SHOT;
        }

        proto = ip6h->nexthdr;
        trans_data = ip6h + 1;
    }

    /* 获取TCP/UDP源端口和目的端口*/
    if (proto == IPPROTO_TCP)  {
        struct tcphdr *tcph = (struct tcphdr *)trans_data;

        if ((void*)(trans_data + sizeof(*tcph)) > data_end) {
            return TC_ACT_SHOT;
        }

        dst = tcph->dest;
        src = tcph->source;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)trans_data;
        if ((void*)(trans_data + sizeof(*udph)) > data_end) {
            return TC_ACT_SHOT;
        }

        dst = udph->dest;
        src = udph->source;
    } else {
        goto found_unknown;
    }

    /* 检查源端口或目的端口是否被允许 */
    if (allow_port(src) || allow_port(dst)) {
        rc = rc_allow;
    }

    /* 打印日志 */
    if (skb->ingress_ifindex) {
        bpf_printk("b ingress on -- src %d dst %d",
            bpf_ntohs(src), bpf_ntohs(dst));
    } else {
        bpf_printk("b  egress on -- src %d dst %d",
            bpf_ntohs(src), bpf_ntohs(dst));
    }

    return rc;

found_unknown:
    rc = TC_ACT_UNSPEC;
    return rc;
}

/* 定义许可证 */
char _license[] SEC("license") = "GPL";