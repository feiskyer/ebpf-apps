#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/bpf.h>

#include "xdp_drop_trace.skel.h"

int main(int argc, char **argv)
{
	unsigned int id = 0;
	int target_fd = -1;
	while(1) {
		int err = bpf_prog_get_next_id(id, &id);
		if (err) {
			fprintf(stderr, "can't get next prog id: %s\n", strerror(errno));
			break;
		}

		int fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0) {
			fprintf(stderr, "can't get fd for prog id %d: %s\n", id, strerror(errno));
			continue;
		}

		struct bpf_prog_info info = {};
		__u32 info_len = sizeof(info);
		err = bpf_prog_get_info_by_fd(fd, &info, &info_len);
		if (err) {
			fprintf(stderr, "can't get info for prog id %d: %s\n", id, strerror(errno));
			continue;
		}

		if (strncmp(info.name, "xdp_prog_drop", sizeof(info.name)) == 0) {
			target_fd = fd;
			break;
		}
	}

	if (target_fd < 0)
	{
		fprintf(stderr, "can't find xdp_prog_drop\n");
		return 1;
	}

	//////////////////////////////////////////
	struct xdp_drop_trace_bpf *obj;
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

	/* load tracing eBPF program */
	obj = xdp_drop_trace_bpf__open();
	if (!obj)
	{
		fprintf(stderr,
						"failed to open and/or load tracing BPF object\n");
		perror("xdp_drop_trace_bpf__open failed");
		return 1;
	}

	struct bpf_program *trace_prog_fentry = obj->progs.trace_on_entry;
	struct bpf_program *trace_prog_fexit = obj->progs.trace_on_exit;
	bpf_program__set_expected_attach_type(trace_prog_fentry,
																				BPF_TRACE_FENTRY);
	bpf_program__set_attach_target(trace_prog_fentry, target_fd,
																 "xdp_prog_drop");
	bpf_program__set_expected_attach_type(trace_prog_fexit,
																				BPF_TRACE_FEXIT);
	bpf_program__set_attach_target(trace_prog_fexit, target_fd,
																 "xdp_prog_drop");

	err = xdp_drop_trace_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load XDP BPF object %d\n", err);
		perror("load XDP BPF object failed");
		goto cleanup;
	}

	err = xdp_drop_trace_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs\n");
		perror("attach BPF programs failed");
		goto cleanup;
	}

	printf("Successfully started! Tracing /sys/kernel/debug/tracing/trace_pipe...\n");

	system("cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
	xdp_drop_trace_bpf__destroy(obj);
	return err != 0;
}
