#ifndef __XDP_PROXY_H__
#define __XDP_PROXY_H__

#include <linux/types.h>
#include <linux/if_ether.h>

#define SVC1_KEY 0x1

struct endpoints {
	__be32 client;
	__be32 ep1;
	__be32 ep2;
	__be32 vip;
	unsigned char ep1_mac[ETH_ALEN];
	unsigned char ep2_mac[ETH_ALEN];
	unsigned char client_mac[ETH_ALEN];
	unsigned char vip_mac[ETH_ALEN];
} __attribute__((packed));

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#endif				/* __XDP_PROXY_H__ */
