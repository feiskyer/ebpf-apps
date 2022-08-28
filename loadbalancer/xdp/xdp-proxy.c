#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include "xdp-proxy.skel.h"

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

	/* Attach the XDP program to eth0 */
	int prog_id = bpf_program__fd(obj->progs.xdp_proxy);
	LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
	err = bpf_xdp_attach(ifindex, prog_id, xdp_flags, &attach_opts);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Successfully run! Tracing /sys/kernel/debug/tracing/trace_pipe.\n");
	system("cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
	/* detach and free XDP program on exit */
	bpf_xdp_detach(ifindex, xdp_flags, &attach_opts);
	xdp_proxy_bpf__destroy(obj);
	return err != 0;
}
