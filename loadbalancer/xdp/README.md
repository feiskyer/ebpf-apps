# XDP eBPF

```sh
# Webserver
docker run -itd --name=http1 --hostname=http1 feisky/webserver
docker run -itd --name=http2 --hostname=http2 feisky/webserver

# Client
docker run -itd --name=client alpine

# LB (XDP would be setup in xdp-proxy)
docker run -itd --name=lb --privileged -v /sys/kernel/debug:/sys/kernel/debug alpine
```
