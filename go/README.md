# eBPF apps in Go

## eBPF Go libraries

| Library | Summary | Dependencies | Stars |
|---------|---------|--------------|-------|
|[cilium/ebpf](https://github.com/cilium/ebpf)|a pure Go library that provides utilities for loading, compiling, and debugging eBPF programs | Linux>=4.4 | 2k |
|[iovisor/gobpf](https://github.com/iovisor/gobpf)|go bindings for the bcc framework as well as low-level routines to load and use eBPF programs from .elf files| [bcc](https://github.com/iovisor/bcc), Runtime LLVM, CGO | 1.5k |
|[aquasecurity/libbpfgo](https://github.com/aquasecurity/libbpfgo)|a Go wrapper around the libbpf project|[libbpf](https://github.com/libbpf/libbpf), CGO| 0.2k |
|[dropbox/goebpf](https://github.com/dropbox/goebpf)|A nice and convenient way to work with eBPF programs / perf events from Go (limited eBPF feature support)|Linux>=4.15| 0.8k |
