#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include "xdp-proxy.skel.h"
#include "xdp-proxy.h"

/* Attach to eth0 by default */
#define DEV_NAME "eth0"

int main(int argc, char **argv)
{
	__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
	struct xdp_proxy_bpf *obj;
	int err = 0;

	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
	if (err)
	{
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}

	unsigned int ifindex = if_nametoindex(DEV_NAME);
	if (ifindex == 0)
	{
		fprintf(stderr, "failed to find interface %s\n", DEV_NAME);
		return 1;
	}

	obj = xdp_proxy_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = xdp_proxy_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	__be32 svc1_key = SVC1_KEY;
	struct endpoints ep =
		{
			/* fixme: replace with your own values if they are different */
			.ep1 = inet_addr("172.17.0.2"),						/* Hex:0x20011ac Dec:33558956 */
			.ep2 = inet_addr("172.17.0.3"),						/* Hex:0x30011ac Dec:50336172 */
			.client = inet_addr("172.17.0.4"),					/* Hex:0x40011ac Dec:67113388 */
			.vip = inet_addr("172.17.0.5"),						/* Hex:0x50011ac Dec:83890604 */
			.ep1_mac = {0x02, 0x42, 0xac, 0x11, 0x00, 0x02},	/* 02:42:ac:11:00:02 */
			.ep2_mac = {0x02, 0x42, 0xac, 0x11, 0x00, 0x03},	/* 02:42:ac:11:00:03 */
			.client_mac = {0x02, 0x42, 0xac, 0x11, 0x00, 0x04}, /* 02:42:ac:11:00:04 */
			.vip_mac = {0x02, 0x42, 0xac, 0x11, 0x00, 0x05},	/* 02:42:ac:11:00:05 */
		};
	int map_id = bpf_map__fd(obj->maps.services);
	err = bpf_map_update_elem(map_id, &svc1_key, &ep, BPF_ANY);
	if (err)
	{
		fprintf(stderr, "failed to update maps\n");
		goto cleanup;
	}

	/* Attach the XDP program to eth0 */
	int prog_id = bpf_program__fd(obj->progs.xdp_proxy);
	err = bpf_set_link_xdp_fd(ifindex, prog_id, xdp_flags);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Successfully run! Tracing /sys/kernel/debug/tracing/trace_pipe.\n");
	system("cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
	/* detach and free XDP program on exit */
	bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	xdp_proxy_bpf__destroy(obj);
	return err != 0;
}
