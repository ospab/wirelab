#!/bin/sh
# Server zone: the proxy server plus what lies behind it: an HTTP target with
# a random blob, and (for Reality) a local TLS 1.3 site to borrow handshakes
# from, so nothing in the lab talks to the outside world.
set -eu
# Offloads off so the wire sees real packet sizes (see wire/entrypoint.sh).
ethtool -K eth0 tso off gso off gro off 2> /dev/null || true
ip route add 10.77.1.0/24 via 10.77.2.2

mkdir -p /srv/www /etc/wl
head -c "$BLOB_BYTES" /dev/urandom > /srv/www/blob
sha256sum /srv/www/blob | cut -d' ' -f1 > /out/server-blob.sha256
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=$SNI" -addext "subjectAltName=DNS:$SNI" \
    -keyout /etc/wl/key.pem -out /etc/wl/cert.pem 2> /dev/null
cat > /etc/wl/nginx.conf <<CONF
worker_processes 1;
error_log /out/server-nginx.log warn;
pid /tmp/nginx.pid;
events {}
http {
    access_log off;
    sendfile on;
    server { listen 127.0.0.1:8080; root /srv/www; }
    server {
        listen 127.0.0.1:8443 ssl;
        http2 on;
        ssl_protocols TLSv1.3;
        ssl_certificate /etc/wl/cert.pem;
        ssl_certificate_key /etc/wl/key.pem;
        root /srv/www;
    }
}
CONF
nginx -c /etc/wl/nginx.conf
exec xray run -c /wl/server.json
