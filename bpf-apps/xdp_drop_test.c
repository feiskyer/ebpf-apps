#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include "xdp_drop_test.skel.h"

#define ICMP_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))
#define TCP_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

char *get_tcp()
{
	char *packet = (char *)malloc(TCP_SIZE);
	memset(packet, 0, TCP_SIZE);

	// Ethernet header
	struct ethhdr *eth = (struct ethhdr *)packet;
	unsigned char dst_mac[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB };
	unsigned char src_mac[] = { 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01 };
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	// IP header
	struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(TCP_SIZE - sizeof(struct ethhdr));
	ip->id = htons(42);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = inet_addr("192.168.5.5");
	ip->daddr = inet_addr("192.168.5.1");
	ip->check = 0;

	// TCP header
	struct tcphdr *tcp =
	    (struct tcphdr *)(packet + sizeof(struct ethhdr) +
			      sizeof(struct iphdr));
	tcp->source = htons(12345);	// Source port
	tcp->dest = htons(80);	// Destination port (e.g., HTTP)
	tcp->seq = htonl(1000);	// Sequence number
	tcp->ack_seq = 0;	// Acknowledgement number
	tcp->doff = 5;		// Data offset
	tcp->fin = 0;
	tcp->syn = 1;		// SYN flag set (connection initiation)
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
	tcp->window = htons(5840);	// Maximum allowed window size
	tcp->check = 0;		// Checksum (set to 0 for now)
	tcp->urg_ptr = 0;

	return packet;
}

char *get_icmp()
{
	char *packet = (char *)malloc(ICMP_SIZE);
	memset(packet, 0, ICMP_SIZE);

	// Ethernet header
	struct ethhdr *eth = (struct ethhdr *)packet;
	char dst_mac[] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA };
	char src_mac[] = { 0x01, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	// IP header
	struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(ICMP_SIZE - sizeof(struct ethhdr));
	ip->id = htons(42);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = inet_addr("192.168.5.5");
	ip->daddr = inet_addr("192.168.5.1");
	ip->check = 0;

	// ICMP header
	struct icmphdr *icmp =
	    (struct icmphdr *)(packet + sizeof(struct ethhdr) +
			       sizeof(struct iphdr));
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = htons(1234);
	icmp->un.echo.sequence = htons(1);

	return packet;
}

int main(int argc, char **argv)
{
	/* 1. construct ICMP and TCP packets */
	char *icmp_packet = get_icmp();
	char *tcp_packet = get_tcp();

	/* 2. construct bpf_test_run_opts */
	struct bpf_test_run_opts opts = {
		.sz = sizeof(struct bpf_test_run_opts),
		.data_in = icmp_packet,
		.data_size_in = ICMP_SIZE,
	};

	/* 3. load the eBPF program */
	struct xdp_drop_test_bpf *obj = xdp_drop_test_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		free(icmp_packet);
		free(tcp_packet);
		return 1;
	}

	/* 4. run the ICMP test */
	int prog_id = bpf_program__fd(obj->progs.xdp_prog_drop);
	int err = bpf_prog_test_run_opts(prog_id, &opts);
	if (err != 0) {
		fprintf(stderr,
			"[FAIL] failed to run bpf_prog_test_run_opts() for ICMP: %d\n",
			err);
		goto cleanup;
	}
	if (opts.retval == XDP_DROP) {
		fprintf(stdout, "[PASS] ICMP packets dropped\n");
	} else {
		fprintf(stdout, "[FAIL] ICMP packets not dropped\n");
	}

	/* 5. run the TCP test */
	struct bpf_test_run_opts tcp_opts = {
		.sz = sizeof(struct bpf_test_run_opts),
		.data_in = tcp_packet,
		.data_size_in = TCP_SIZE,
	};
	err = bpf_prog_test_run_opts(prog_id, &tcp_opts);
	if (err != 0) {
		fprintf(stderr,
			"[FAIL] failed to run bpf_prog_test_run_opts() for TCP: %d\n",
			err);
		goto cleanup;
	}
	if (tcp_opts.retval == XDP_PASS) {
		fprintf(stdout, "[PASS] TCP packets passed\n");
	} else {
		fprintf(stdout, "[FAIL] TCP packets not passed\n");
	}

 cleanup:
	xdp_drop_test_bpf__destroy(obj);
	free(icmp_packet);
	free(tcp_packet);
	return err != 0;
}
