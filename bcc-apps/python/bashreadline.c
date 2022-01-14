/* Tracing bash's readline retval */
#include <uapi/linux/ptrace.h>

struct data_t {
	u32 uid;
	char command[64];
};
BPF_PERF_OUTPUT(events);

int bash_readline(struct pt_regs *ctx)
{
	struct data_t data = { };
	data.uid = bpf_get_current_uid_gid();

	// PT_REGS_RC(ctx) holds the return value.
	bpf_probe_read_user(&data.command, sizeof(data.command),
			    (void *)PT_REGS_RC(ctx));

	// submit perf event.
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
