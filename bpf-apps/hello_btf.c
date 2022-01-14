/*
*   Hello world custom BTF file for kernel without built-in BTF support
*
*   The BTF file could be got by
*   * either 1) download from https://github.com/aquasecurity/btfhub-archive
*   * or 2) pahole --btf_encode <binary>.
*
*   Run with the following command:
*      export BPF_CUSTOM_BTF=<downloaded>.btf
*      ./hello-btf
*/
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "hello_btf.skel.h"

int main(int argc, char **argv)
{
	struct hello_btf_bpf *obj;
	int err = 0;

	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}
	struct bpf_object_open_opts openopts = {
		.sz = sizeof(struct bpf_object_open_opts),
		.btf_custom_path = getenv("BPF_CUSTOM_BTF"),
	};
	obj = hello_btf_bpf__open_opts(&openopts);
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = hello_btf_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	err = hello_btf_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf
	    ("Successfully started! Tracing /sys/kernel/debug/tracing/trace_pipe...\n");

	system("cat /sys/kernel/debug/tracing/trace_pipe");

 cleanup:
	hello_btf_bpf__destroy(obj);
	return err != 0;
}
