# XDP eBPF

```sh
# Webserver
docker run -itd --name=http1 --hostname=http1 feisky/webserver
docker run -itd --name=http2 --hostname=http2 feisky/webserver

# Client
docker run -itd --name=client alpine

# LB (XDP would be setup in xdp-proxy)
docker run -itd --name=lb --privileged -v /sys/kernel/debug:/sys/kernel/debug alpine
docker cp xdp-proxy lb:/ # or for v2, run "docker cp xdp-proxy-v2  lb:/"
docker exec -it lb /xdp-proxy

# Open a new termnial and test the client
docker exec -it client apk add curl --update
docker exec -it client curl "http://172.17.0.5"
```
