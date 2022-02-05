#ifndef __XDP_PROXY_H__
#define __XDP_PROXY_H__

#include <linux/types.h>

#define SVC1_KEY 0x1

struct endpoints {
	__be32 client;
	__be32 ep1;
	__be32 ep2;
	__be32 vip;
};

#endif				/* __XDP_PROXY_H__ */
