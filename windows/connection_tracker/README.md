# eBPF For Windows Demo - Connection Tracking

This project demonstrates the following features adapted from [eBPF for Windows demo](https://github.com/microsoft/ebpf-for-windows-demo/tree/main/connection_tracker):

1) Native eBPF program generation.
2) The BPF_PROG_TYPE_SOCK_OPS program type.
3) The bpf_printk helper emitting tracing to ETW.
4) The BPF_MAP_TYPE_RINGBUF map type.

The project provides a real-time list of connections that have been completed along with the source, destination, and duration of each connection.

## How to run

### Build BPF_PROG_TYPE_SOCK_OPS and BPF_MAP_TYPE_RINGBUF demo

1) Build the ```ebpf-for-windows-demo``` as outlined in [Getting Started](https://github.com/microsoft/ebpf-for-windows-demo/blob/main/docs/GettingStarted.md).
2) [Install eBPF-For-Windows with the msi installer](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md#method-1-install-a-release-with-the-msi-installer) on the target machine. This should start netebpfext, ebpfcore and ebpfsvc services.
3) Copy conn_track.sys and conn_tracker.exe to the target machine.
4) Launch conn_tracker.exe.
5) Launch a browser and navigate to any website.
6) Connection tracker will then show the list of connections.

## How to view logs

1) Start an ETW session and add the eBPF-For-Windows provider: ```tracelog -start MyTrace -guid C:\ebpf-for-windows\ebpf-printk.guid -rt```.
2) Start a real-time trace consumer: ```tracefmt -rt MyTrace -displayonly -jsonMeta 0```.
3) Launch conn_tracker.exe.
4) Launch a browser and navigate to any website.
5) The real-time trace consumer will then show all the bpf_printk events being generated by the eBPF program.