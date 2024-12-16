// Uncomment this line if don't have BTF on the running machine.
// #define BPF_NO_PRESERVE_ACCESS_INDEX

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "execsnoop.h"

static const struct event empty_event = { };

// define hash map and perf event map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
}
events SEC(".maps");

// tracepoint for sys_enter_execve.
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter
					   *ctx)
{
	struct event *event;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

	// get the PID
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = (pid_t) id;

	// update the exec metadata to execs map
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST)) {
		return 0;
	}
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event) {
		return 0;
	}
	// update event metadata
	event->pid = pid;
	event->args_count = 0;
	event->args_size = 0;

	// query the first parameter
	unsigned int ret = bpf_probe_read_user_str(event->args, ARGSIZE,
						   (const char *)ctx->args[0]);
	if (ret <= ARGSIZE) {
		event->args_size += ret;
	} else {
		/* write an empty string */
		event->args[0] = '\0';
		event->args_size++;
	}

	// query the extra parameters
	event->args_count++;
#pragma unroll
	for (int i = 1; i < TOTAL_MAX_ARGS; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret =
		    bpf_probe_read_user_str(&event->args[event->args_size],
					    ARGSIZE, argp);
		if (ret > ARGSIZE)
			return 0;

		event->args_count++;
		event->args_size += ret;
	}

	/* try to read one more argument to check if there is one */
	bpf_probe_read_user(&argp, sizeof(argp), &args[TOTAL_MAX_ARGS]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, assume we have more arguments */
	event->args_count++;

	return 0;
}

// tracepoint for sys_exit_execve.
SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
	u64 id;
	pid_t pid;
	int ret;
	struct event *event;

	// get the exec metadata from execs map
	id = bpf_get_current_pid_tgid();
	pid = (pid_t) id;
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	// update event retval
	ret = ctx->ret;
	event->retval = ret;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// submit to perf event
	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
				      len);

	// cleanup exec from hash map
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
