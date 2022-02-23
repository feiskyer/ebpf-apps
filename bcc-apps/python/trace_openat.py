#!/usr/bin/env python3
# Tracing openat() system call.
from bcc import BPF
from bcc.utils import printb

prog =''' 
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

// define the output data structure.
struct data_t {
	u32 pid;
	u64 ts;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
	struct data_t data = { };

	data.pid = bpf_get_current_pid_tgid();
	data.ts = bpf_ktime_get_ns();
	if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
		bpf_probe_read_user(&data.fname, sizeof(data.fname), args->filename);
	}

	events.perf_submit(args, &data, sizeof(data));
	return 0;
}
'''

# 1) load BPF program
b = BPF(text=prog)

# 2) print header
print("%-18s %-16s %-6s %-16s" % ("TIME(s)", "COMM", "PID", "FILE"))

# 3) define the callback for perf event
start = 0


def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(b"%-18.9f %-16s %-6d %-16s" % (time_s, event.comm, event.pid, event.fname))


# 4) loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
