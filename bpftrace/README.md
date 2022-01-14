# eBPF apps with bpftrace

bpftrace is a high-level tracing language for Linux enhanced Berkeley Packet Filter (eBPF) available in recent Linux kernels (4.x+). bpftrace uses LLVM as a backend to compile scripts to BPF-bytecode and makes use of [BCC](https://github.com/iovisor/bcc) for interacting with the Linux BPF system, as well as existing Linux tracing capabilities: kernel dynamic tracing (kprobes), user-level dynamic tracing (uprobes), and tracepoints. The bpftrace language is inspired by awk and C, and predecessor tracers such as DTrace and SystemTap.

## Install

```sh
# Ubuntu 19.04+
sudo apt-get install -y bpftrace

# RHEL8+/CentOS8+
sudo dnf install -y bpftrace
```
