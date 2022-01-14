# eBPF w/ kernel

eBPF apps built with kernel source code.

## Pre-requisites

* Download kernel source code and build kernel's BPF lib under `tools/lib/bpf`.

## How to build and run

```sh
export KERNEL_SOURCE=<replace-this>
make
sudo ./hello
```

