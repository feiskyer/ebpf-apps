#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/tcp.h"

SEC("xdp")
int DropPacket(xdp_md_t *ctx)
{
    /* abort on illegal packets */
    if ((char*)ctx->data + sizeof(ETHERNET_HEADER) > (char*)ctx->data_end) {
        return XDP_DROP;
    }

    ETHERNET_HEADER* ethernet_header = (ETHERNET_HEADER *)ctx->data;
    if (ethernet_header->Type == bpf_htons(ETHERNET_TYPE_IPV4))
    {
        if ((char*)ctx->data + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) > (char*)ctx->data_end)
        {
            return XDP_PASS;
        }

        IPV4_HEADER* ipv4_header = (IPV4_HEADER*)(ethernet_header + 1);
        if (ipv4_header->Protocol == IPPROTO_TCP) {
            char* next_header = (char*)ipv4_header + sizeof(uint32_t) * ipv4_header->HeaderLength;
            if ((char*)next_header + sizeof(struct tcphdr) > (char*)ctx->data_end) {
                return XDP_PASS;
            }

            struct tcphdr* tcp_header = (struct tcphdr*)((char*)ipv4_header + sizeof(uint32_t) * ipv4_header->HeaderLength);
            /* drop packets to TCP port 80 */
            if (bpf_ntohs(tcp_header->dest) == 80)
            {
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}
