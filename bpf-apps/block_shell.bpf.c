/* Blocking all bash commands */
/* Require: "CONFIG_BPF_LSM=y" and CONFIG_LSM="bpf,..." */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

#ifndef NULL
#define NULL 0
#endif

static __always_inline int handle_new_process(struct task_struct *parent,
					      struct task_struct *child)
{
	char bash[] = "bash";

	pid_t pid = BPF_CORE_READ(child, pid);
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	u64 pidns = child->nsproxy->pid_ns_for_children->ns.inum;

	for (int i = 0; i < sizeof(bash); i++) {
		if (comm[i] != bash[i]) {
			return 0;
		}
	}

	bpf_printk("lsm: blocking %s (pid: %d) in pidns %ld\n", comm, pid,
		   pidns);
	return -EPERM;
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags,
	     int ret_prev)
{
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent == NULL) {
		return -EPERM;	/* Shouldn't happen */
	}

	/* Handle results of previous programs */
	if (ret_prev != 0) {
		return ret_prev;
	}

	return handle_new_process(parent, task);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
