#!/usr/bin/env python3
# This is a Hello World example of BPF.
from bcc import BPF

# load BPF program
b = BPF(src_file="hello.c")
b.attach_kprobe(event="do_sys_openat2", fn_name="hello_world")
b.trace_print()
