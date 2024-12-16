#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "xdp_drop.skel.h"
#include "xdp_drop_trace.skel.h"

int main(int argc, char **argv)
{
	struct xdp_drop_trace_bpf *obj;
	struct xdp_drop_bpf *xdp_obj;
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

	/* load target eBPF program */
	xdp_obj = xdp_drop_bpf__open();
	if (!xdp_obj) {
		fprintf(stderr,
			"failed to open and/or load xdp_drop BPF object\n");
		perror("xdp_drop_bpf__open failed");
		return 1;
	}
	int xdp_fd = bpf_program__fd(xdp_obj->progs.xdp_prog_drop);

	/* load tracing eBPF program */
	obj = xdp_drop_trace_bpf__open();
	if (!obj) {
		fprintf(stderr,
			"failed to open and/or load tracing BPF object\n");
		perror("xdp_drop_trace_bpf__open failed");
		return 1;
	}
	// const struct btf *btf = bpf_object__btf(obj->obj);
	// if (!btf)
	// {
	//      fprintf(stderr, "failed to get BTF object\n");
	//      goto cleanup;
	// }

	// // Find BTF ID of 'xdp_prog_drop'
	// int func_id = -1;
	// int type_cnt = btf__type_cnt(btf);

	// for (int i = 1; i <= type_cnt; i++)
	// {
	//      const struct btf_type *t = btf__type_by_id(btf, i);
	//      if (!t)
	//              continue;
	//      if (btf_kind(t) != BTF_KIND_FUNC)
	//              continue;
	//      const char *name = btf__name_by_offset(btf, t->name_off);
	//      if (strcmp(name, "xdp_prog_drop") == 0)
	//      {
	//              func_id = i;
	//              break;
	//      }
	// }
	// if (func_id < 0)
	// {
	//      fprintf(stderr, "failed to find BTF ID for 'xdp_prog_drop'\n");
	//      goto cleanup;
	// }

	struct bpf_program *trace_prog_fentry = obj->progs.trace_on_entry;
	struct bpf_program *trace_prog_fexit = obj->progs.trace_on_exit;
	bpf_program__set_expected_attach_type(trace_prog_fentry,
					      BPF_TRACE_FENTRY);
	bpf_program__set_attach_target(trace_prog_fentry, xdp_fd,
				       "xdp_prog_drop");
	bpf_program__set_expected_attach_type(trace_prog_fexit,
					      BPF_TRACE_FEXIT);
	bpf_program__set_attach_target(trace_prog_fexit, xdp_fd,
				       "xdp_prog_drop");

	// trace_prog_fentry->attach_btf_id = func_id;
	// trace_prog_fentry->attach_btf_obj_fd = btf__fd(btf);
	//      trace_prog_fexit->attach_btf_id = func_id;
	// trace_prog_fexit->attach_btf_obj_fd = btf__fd(btf);

	// bpf_program__set_expected_attach_type(trace_prog_fentry, BPF_TRACE_FENTRY);
	// bpf_program__set_attach_target(trace_prog_fentry, 0, "xdp_prog_drop");
	// bpf_program__set_expected_attach_type(trace_prog_fexit, BPF_TRACE_FEXIT);
	// bpf_program__set_attach_target(trace_prog_fexit, 0, "xdp_prog_drop");
// Ensure that the attach target "xdp_prog_drop" is correct.
// Replace "xdp_prog_drop" with the actual target function name if necessary.

	// bpf_program__set_autoload(trace_prog_fentry, false);
	// bpf_program__set_autoload(trace_prog_fexit, false);
	// bpf_program__set_autoattach(trace_prog_fentry, false);
	// bpf_program__set_autoattach(trace_prog_fexit, false);

	err = xdp_drop_trace_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load XDP BPF object %d\n", err);
		perror("load XDP BPF object failed");
		goto cleanup;
	}
	// int prog_id = bpf_program__fd(obj->progs.xdp_prog_drop);
	// LIBBPF_OPTS(bpf_prog_load_opts, load_opts,
	//                                              // .expected_attach_type = bpf_program__get_expected_attach_type(trace_prog_fentry),
	//                                              // .attach_btf_obj_fd = btf__fd(btf),
	//                                              // .attach_btf_id = func_id,
	//      );
	// err = bpf_prog_load(
	//              bpf_program__type(trace_prog_fentry),
	//              bpf_program__name(trace_prog_fentry),
	//              "Dual BSD/GPL",
	//              bpf_program__insns(trace_prog_fentry),
	//              bpf_program__insn_cnt(trace_prog_fentry),
	//              &load_opts);
	// if (err)
	// {
	//              fprintf(stderr, "failed to load fentry BPF object %d\n", err);
	//              perror("load fentry BPF object failed");
	//              goto cleanup;
	// }

	// //           // Proceed with setting up the attach parameters
	// bpf_program__set_expected_attach_type(trace_prog_fentry, BPF_TRACE_FENTRY);
	// bpf_program__set_attach_target(trace_prog_fentry, prog_id, "xdp_prog_drop");
	// //           // // // bpf_program__set_attach_btf_id(trace_prog_fentry, "xdp_prog_drop");
	// bpf_program__set_expected_attach_type(trace_prog_fexit, BPF_TRACE_FEXIT);
	// bpf_program__set_attach_target(trace_prog_fexit, prog_id, "xdp_prog_drop");
	// //           // // // bpf_program__set_attach_btf_id(trace_prog_fexit, "xdp_prog_drop");
	// // bpf_program__set_autoload(trace_prog_fentry, true);
	// // bpf_program__set_autoload(trace_prog_fexit, true);
	// // bpf_program__set_autoload(obj->progs.xdp_prog_drop, false);
	// // err = bpf_object__load(trace_prog_fentry->bpf_obj);
	// // if (err)
	// // {
	// //   fprintf(stderr, "failed to load BPF object %d\n", err);
	// //   goto cleanup;
	// // }

	// DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	// opts.target_btf_id = func_id;
	// int lfd = bpf_link_create(bpf_program__fd(obj->progs.trace_on_entry),
	//                                                                                      prog_id, 0, &opts); // bpf_program__attach(trace_prog_fentry);
	// if (lfd < 0)
	// {
	//      fprintf(stderr, "failed to attach trace_on_entry: %s\n", strerror(-lfd));
	//      goto cleanup;
	// }

	//              lfd = bpf_link_create(bpf_program__fd(obj->progs.trace_on_exit),
	//                                                                                                      prog_id, 0, &opts);
	//              if (lfd < 0)
	//              {
	//                      fprintf(stderr, "failed to attach trace_on_exit: %s\n", strerror(-lfd));
	//                      goto cleanup;
	// }

	/* Attach the XDP program to the specified network interface */
	// err = bpf_xdp_attach(ifindex, prog_id, xdp_flags, &attach_opts);
	// if (err) {
	//      fprintf(stderr, "failed to attach BPF programs\n");
	//      goto cleanup;
	// }

	err = xdp_drop_trace_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		perror("attach BPF programs failed");
		goto cleanup;
	}

	printf
	    ("Successfully started! Tracing /sys/kernel/debug/tracing/trace_pipe...\n");

	system("cat /sys/kernel/debug/tracing/trace_pipe");

 cleanup:
	// bpf_xdp_detach(ifindex, xdp_flags, &attach_opts);
	xdp_drop_trace_bpf__destroy(obj);
	xdp_drop_bpf__destroy(xdp_obj);
	return err != 0;
}
