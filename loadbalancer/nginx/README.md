# LoadBalancer with nginx

## Step1: Start containers

```sh
# Webserver
docker run -itd --name=http1 --hostname=http1 feisky/webserver
docker run -itd --name=http2 --hostname=http2 feisky/webserver

# Client
docker run -itd --name=client alpine

# Nginx as LB
docker run -itd --name=nginx nginx
```

## Step2: Generate nginx configuration

```sh
IP1=$(docker inspect http1 -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
IP2=$(docker inspect http2 -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

cat>nginx.conf <<EOF
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
   include       /etc/nginx/mime.types;
   default_type  application/octet-stream;

    upstream webservers {
        server $IP1;
        server $IP2;
    }

    server {
        listen 80;

        location / {
            proxy_pass http://webservers;
        }
    }
}
EOF
```

## Step3: Update nginx configuration

```sh
docker cp nginx.conf nginx:/etc/nginx/nginx.conf
docker exec nginx nginx -s reload
```

## Step4: Http test

```sh
$ docker inspect nginx -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
172.17.0.5

$ docker exec -it client sh
/ # apk add curl wrk --update
/ # curl "http://172.17.0.5"
/ # wrk "http://172.17.0.5"
```
