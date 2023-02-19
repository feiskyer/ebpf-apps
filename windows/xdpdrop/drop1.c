#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/tcp.h"

SEC("xdp")
int DropPacket(xdp_md_t *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

     struct ethhdr *eth = data;
     /* abort on illegal packets */
     if (data + sizeof(struct ethhdr) > data_end)
     {
         return XDP_DROP;
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
         return XDP_DROP;
     }

     /* do nothing for non-TCP packets */
     if (iph->protocol != IPPROTO_TCP)
     {
         return XDP_PASS;
     }

     struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
     /* abort on illegal packets */
     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) // ((void *)(tcph + 1) > data_end)
     {
         return XDP_DROP;
     }

     /* drop packets to TCP port 80 */
     if (bpf_ntohs(tcph->dest) == 80)
     {
         return XDP_DROP;
     }

    return XDP_PASS;
}
