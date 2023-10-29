# Windows eBPF Hello World

```powershell
# Build
clang -I 'C:\ebpf-for-windows\include' -target bpf -Werror -O2 -g -c bpf.c -o bpf.o

# Load
netsh ebpf add program bpf.o
```
