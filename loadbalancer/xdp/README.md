# XDP eBPF

```sh
# Webserver
docker run -itd --name=http1 --hostname=http1 feisky/webserver
docker run -itd --name=http2 --hostname=http2 feisky/webserver

# Client
docker run -itd --name=client alpine

# LB
docker run -itd --name=lb -v /sys:/sys --privileged alpine
```
