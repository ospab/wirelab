#!/bin/sh
# A lab node (client or server) waiting for a person: routes through the
# wire, offloads off so the wire sees real packet sizes, and on the server
# an HTTP target with a test blob on 127.0.0.1:8080.
set -eu
ethtool -K eth0 tso off gso off gro off 2> /dev/null || true
case "$ROLE" in
    client) ip route add 10.77.2.0/24 via 10.77.1.2 ;;
    server) ip route add 10.77.1.0/24 via 10.77.2.2 ;;
esac

if [ "$ROLE" = server ]; then
    mkdir -p /srv/www
    head -c "${BLOB_BYTES:-20000000}" /dev/urandom > /srv/www/blob
    sha256sum /srv/www/blob | cut -d' ' -f1 > /srv/www/blob.sha256
    cat > /tmp/nginx.conf <<CONF
worker_processes 1;
error_log /tmp/nginx-error.log warn;
pid /tmp/nginx.pid;
events {}
http {
    access_log off;
    sendfile on;
    server { listen 127.0.0.1:8080; root /srv/www; }
}
CONF
    nginx -c /tmp/nginx.conf
fi

trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
