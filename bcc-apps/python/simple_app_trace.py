#!/usr/bin/python3
#
# Tracing Python USDT.
# Start ./simple_app.py before starting this trace script.
import subprocess
from bcc import BPF, USDT
from bcc.utils import printb

prog = """#include <uapi/linux/ptrace.h>

struct data_t {
	int a;
    int b;
};
BPF_PERF_OUTPUT(events);

int print_functions(struct pt_regs *ctx)
{
	uint64_t argptr;
	struct data_t data = { };

    /* function__entry params are (int a, int b) */
	bpf_usdt_readarg(1, ctx, &data.a);
	bpf_usdt_readarg(2, ctx, &data.b);
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
};
"""

# find the PID for "simple_app.py"
cmd = subprocess.Popen(
    ["pgrep", "-f", "simple_app.py"], stdout=subprocess.PIPE, shell=False
).communicate()
if cmd[0]:
    pid = int(cmd[0].decode("ascii").strip())
else:
    print("ERROR: cannot find PID for simple_app.py")
    exit()

# load BPF program
u = USDT(pid=pid)
u.enable_probe(probe="sum", fn_name="print_functions")
b = BPF(text=prog, usdt_contexts=[u])


# callback for perf event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-6d %-6d" % (event.a, event.b))


# print header
print("%-6s %-6s" % ("a", "b"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
