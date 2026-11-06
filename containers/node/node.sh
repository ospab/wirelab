#!/bin/sh
# A lab node. client and server route through the wire, with offloads off so
# the wire sees real packet sizes. target is the internet behind the server:
# reachable from the server only, so the client gets there through its proxy
# or not at all.
#
# A node runs /lab/setup.sh at start when there is one, so what you install
# and configure survives the containers being recreated.
set -eu
for i in $(ls /sys/class/net); do ethtool -K "$i" tso off gso off gro off 2> /dev/null || true; done
case "$ROLE" in
    client) ip route add 10.77.2.0/24 via 10.77.1.2 ;;
    server) ip route add 10.77.1.0/24 via 10.77.2.2 ;;
esac

serve() {
    # $1: listen address. Objects for the workloads: one large blob, and
    # small ones the size of a web page's assets.
    mkdir -p /srv/www/obj
    head -c "${BLOB_BYTES:-20000000}" /dev/urandom > /srv/www/blob
    sha256sum /srv/www/blob | cut -d' ' -f1 > /srv/www/blob.sha256
    i=1
    while [ $i -le 40 ]; do
        head -c $((2000 + i * 700)) /dev/urandom > /srv/www/obj/$i
        i=$((i + 1))
    done
    mkdir -p /srv/www/up /tmp/nginx-body
    chmod 777 /srv/www/up /tmp/nginx-body
    # /up/ takes uploads (PUT) and gives them back, so an upload's integrity
    # is checked on the far side; DELETE clears them.
    cat > /tmp/nginx.conf <<CONF
worker_processes 2;
error_log /tmp/nginx-error.log warn;
pid /tmp/nginx.pid;
events {}
http {
    access_log off;
    sendfile on;
    client_body_temp_path /tmp/nginx-body;
    server {
        listen $1;
        root /srv/www;
        location /up/ { dav_methods PUT DELETE; create_full_put_path on; client_max_body_size 0; }
    }
}
CONF
    nginx -c /tmp/nginx.conf
}

case "$ROLE" in
    target) serve 0.0.0.0:80 ;;
    # Kept for labs and recipes written before the target container.
    server) serve 127.0.0.1:8080 ;;
esac

if [ -f /lab/setup.sh ]; then
    (
        echo "--- setup.sh started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        rc=0
        sh /lab/setup.sh || rc=$?
        echo "--- setup.sh exited $rc"
    ) >> /lab/setup.log 2>&1 &
fi

trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
