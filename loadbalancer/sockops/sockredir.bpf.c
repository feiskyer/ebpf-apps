#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>
#include "sockops.h"

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
	struct sock_key key = {
		.sip = msg->remote_ip4,
		.dip = msg->local_ip4,
		.dport = bpf_htonl(msg->local_port),	// convert to network byte order
		.sport = msg->remote_port,
		.family = msg->family,
	};

	bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
	return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
