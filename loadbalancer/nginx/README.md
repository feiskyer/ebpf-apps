# LoadBalancer with nginx

How to update Nginx config dynamically:

```sh
# Start a normal nginx container
docker run -itd --name=nginx nginx

# Update config
docker cp nginx.conf nginx:/etc/nginx/nginx.conf

# Reload config
docker exec nginx nginx -s reload
```
