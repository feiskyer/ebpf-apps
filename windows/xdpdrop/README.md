# XDP DropPacket

## Compile and Load

```sh
clang -I 'C:\ebpf-for-windows\include' -target bpf -Werror -O2 -g -c xdpdrop.c -o xdpdrop.o
netsh ebpf add prog xdpdrop.o xdp # interface="xxx"
```

## Start http server and curl from a different machine

```sh
# Run http server on local machine
python.exe -m http.server 80

# Curl from a different machine
curl.exe -v http://<machine-ip>
```

## Unload

```sh
netsh ebpf delete program id=65540
```
