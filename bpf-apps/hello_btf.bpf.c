#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter
					   *ctx)
{
	const char *filename = (const char *)(ctx->args[0]);
	pid_t pid = bpf_get_current_pid_tgid();

	bpf_printk("Process[%d]: %s\n", pid, filename);
	return 0;
}
