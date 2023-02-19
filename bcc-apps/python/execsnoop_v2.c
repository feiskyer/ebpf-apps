/* Tracing execve system call. */
#include <linux/sched.h>
#include <linux/fs.h>

// consts for arguments (ensure below stack size limit 512)
#define ARGSIZE 64
#define TOTAL_MAX_ARGS 5
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

// perf event map (sharing data to userspace) and hash map (sharing data between tracepoints)
struct data_t {
	u32 pid;
	char comm[TASK_COMM_LEN];
	int retval;
	unsigned int args_size;
	char argv[FULL_MAX_ARGS_ARR];
};
BPF_PERF_OUTPUT(events);
BPF_HASH(tasks, u32, struct data_t);

// helper function to read string from userspace.
static int __bpf_read_arg_str(struct data_t *data, const char *ptr)
{
	if (data->args_size > LAST_ARG) {
		return -1;
	}

	int ret = bpf_probe_read_user_str(&data->argv[data->args_size], ARGSIZE,
					  (void *)ptr);
	if (ret > ARGSIZE || ret < 0) {
		return -1;
	}
	// increase the args size. the first tailing '\0' is not counted and hence it
	// would be overwritten by the next call.
	data->args_size += (ret - 1);

	return 0;
}

// help function to read given size of data from ptr.
static int __bpf_read_arg(struct data_t *data, const char *ptr, int size)
{
	if (data->args_size > LAST_ARG) {
		return -1;
	}

	int ret =
	    bpf_probe_read(&data->argv[data->args_size], ARGSIZE, (void *)ptr);
	if (ret < 0) {
		return -1;
	}

	data->args_size += size;
	return 0;
}

// sys_enter_execve tracepoint.
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
	// variables definitions
	const char spaces[] = " ";
	const char ellipsis[] = "...";
	unsigned int ret = 0;

	// tracepoint arguments are available in args struct, which are same as tracepoint arguments.
	const char **argv = (const char **)(args->argv);

	// get the pid and comm
	struct data_t data = { };
	u32 pid = bpf_get_current_pid_tgid();
	data.pid = pid;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	// get the binary name (first argment)
	if (__bpf_read_arg_str(&data, (const char *)argv[0]) < 0) {
		goto out;
	}
	// append a space for better reading
	if (__bpf_read_arg(&data, (const char *)spaces, 1) < 0) {
		goto out;
	}
	// get other arguments (skip first arg because it has already been read)
#pragma unroll
	for (int i = 1; i < TOTAL_MAX_ARGS; i++) {
		if (__bpf_read_arg_str(&data, (const char *)argv[i]) < 0) {
			goto out;
		}
		// append a space for better reading
		if (i < TOTAL_MAX_ARGS - 1
		    && __bpf_read_arg(&data, (const char *)spaces, 1) < 0) {
			goto out;
		}
	}

	// handle truncated argument list by showing "..." at the end
	if (data.args_size < FULL_MAX_ARGS_ARR - 4) {
		__bpf_read_arg(&data, (const char *)ellipsis, 3);
	}

 out:
	// store the data in hash map
	tasks.update(&pid, &data);
	return 0;
}

// sys_exit_execve tracepoint
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
	// query the data from hash map
	u32 pid = bpf_get_current_pid_tgid();
	struct data_t *data = tasks.lookup(&pid);

	// submit perf events after getting the retval
	if (data != NULL) {
		data->retval = args->ret;
		events.perf_submit(args, data, sizeof(struct data_t));

		// clean up the hash map
		tasks.delete(&pid);
	}

	return 0;
}
