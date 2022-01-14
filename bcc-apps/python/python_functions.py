#!/usr/bin/python3
#
# Tracing Python functions
import subprocess
from bcc import BPF, USDT
from bcc.utils import printb

# find the PID for "python3 -m http.server"
cmd = subprocess.Popen(
    ["pgrep", "-f", "http.server"], stdout=subprocess.PIPE, shell=False
).communicate()
if cmd[0]:
    pid = int(cmd[0].decode("ascii").strip())
else:
    print("ERROR: cannot find PID for python3 -m http.server")
    exit()

# load BPF program
u = USDT(pid=pid)
u.enable_probe(probe="function__entry", fn_name="print_functions")
b = BPF(src_file="python-functions.c", usdt_contexts=[u])


# callback for perf event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-9s %-6d %s" % (event.filename, event.lineno, event.funcname))


# print header
print("%-9s %-6s %s" % ("FILENAME", "LINENO", "FUNCTION"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
