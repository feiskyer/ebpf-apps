#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>
#include "sockops.h"

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	/* skip if the packet is not ipv4 */
	if (skops->family != AF_INET) {
		return BPF_OK;
	}

	/* skip if it is not established op */
	if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
	    && skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
		return BPF_OK;
	}

	struct sock_key key = {
		.dip = skops->remote_ip4,
		.sip = skops->local_ip4,
		/* convert to network byte order */
		.sport = bpf_htonl(skops->local_port),
		.dport = skops->remote_port,
		.family = skops->family,
	};

	bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
	return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
