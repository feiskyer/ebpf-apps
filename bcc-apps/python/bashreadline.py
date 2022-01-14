#!/usr/bin/env python3
# Tracing bash's readline retval
from bcc import BPF
from time import strftime

# load BPF program
b = BPF(src_file="bashreadline.c")

# attach uretprobe
b.attach_uretprobe(name="/usr/bin/bash", sym="readline", fn_name="bash_readline")


# callback for perf event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(
        "%-9s %-6d %s"
        % (strftime("%H:%M:%S"), event.uid, event.command.decode("utf-8"))
    )


# print header
print("%-9s %-6s %s" % ("TIME", "UID", "COMMAND"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
