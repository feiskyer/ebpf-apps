# eBPF apps with [libbpf](https://github.com/libbpf/libbpf)

## Contents

* `hello`: hello world for libbpf.
* `execsnoop` and `execsnoop_v2`: kprobe for tracepoint/syscalls/sys_enter_execve.
* `bashreadline`: uprobe for bash's readline.
* `hello_btf`: custom BTF Hello world for kernel without built-in BTF support.

## Pre-requisites

To use BTF and CO-RE, `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y` need to be enabled. If you don't want to rebuild the kernel, the following distos have enabled those options by default:

* Ubuntu 20.10+
* Fedora 31+
* RHEL 8.2+
* Debian 11+

And to build bpf applications, the following development tools should also be installed:

```sh
# Ubuntu
sudo apt-get install -y make clang llvm libelf-dev linux-tools-$(uname -r)

# RHEL
sudo yum install -y make clang llvm elfutils-libelf-devel bpftool
```
