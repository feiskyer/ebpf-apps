/* Tracing Python functions */
#include <uapi/linux/ptrace.h>

struct data_t {
	char filename[128];
	char funcname[128];
	int lineno;
};
BPF_PERF_OUTPUT(events);

int print_functions(struct pt_regs *ctx)
{
	uint64_t argptr;
	struct data_t data = { };

	/* function__entry params are (str filename, str funcname, int lineno) */
	bpf_usdt_readarg(1, ctx, &argptr);
	bpf_probe_read_user(&data.filename, sizeof(data.filename),
			    (void *)argptr);
	bpf_usdt_readarg(2, ctx, &argptr);
	bpf_probe_read_user(&data.funcname, sizeof(data.funcname),
			    (void *)argptr);
	bpf_usdt_readarg(3, ctx, &data.lineno);

	// submit perf event.
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
};
