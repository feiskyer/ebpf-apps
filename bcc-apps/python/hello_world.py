#!/usr/bin/python3
#
# This is a Hello World example of BPF.
from bcc import BPF

# define BPF program
prog = """
int kprobe__sys_clone(void *ctx)
{
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.trace_print()
