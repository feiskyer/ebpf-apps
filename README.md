# ebpf-apps

eBPF sample apps based on [BCC](https://github.com/iovisor/bcc), [libbpf](https://github.com/libbpf/libbpf) and various language bindings.

## Contents

* [bcc-apps](bcc-apps): eBPF samples with BCC.
  * [bcc-apps/c](bcc-apps/c): BCC samples with C binding.
  * [bcc-apps/cpp](bcc-apps/cpp): BCC samples with C++ binding.
  * [bcc-apps/python](bcc-apps/python): BCC samples with Python binding.
* [bpf-apps](bpf-apps): eBPF samples with libbpf and CO-RE.
* [bpftrace](bpftrace): eBPF samples with bpftrace.
* [go](go): eBPF samples with Go bindings.
* [kernel](kernel): eBPF samples built with kernel source.
* [rust](rust): eBPF samples with Rust bindings.
* [tools](tools): Tools for eBPF (e.g. bpftool and faddr2line).

## Pre-requisites

### BCC

[BCC](https://github.com/iovisor/bcc) and its development libraries should be installed.

#### Install from packages

Please follow [INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md) to see the detailed guides. For example, on Ubuntu or RHEL:

```sh
# Ubuntu
sudo apt-get install bpfcc-tools libbpfcc-dev linux-headers-$(uname -r)

# RHEL
sudo yum install bcc-tools bcc-devel
```

#### Install from source

Please follow [INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md#source) to see the detailed guides. For example, on Ubuntu 20.04+:

```sh
sudo apt install -y bison build-essential cmake flex git libedit-dev llvm-dev libclang-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

### libbpf with CO-RE

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

## Useful Links

* [极客时间专栏《eBPF 核心技术与实战》](https://time.geekbang.org/column/intro/100104501)
* [eBPF.io](https://ebpf.io/)
* [Linux kernel BPF samples](https://elixir.bootlin.com/linux/v5.13/source/samples/bpf)
* [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
* [XDP Hands-On Tutorial](https://github.com/xdp-project/xdp-tutorial)
