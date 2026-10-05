#!/bin/sh
# Client zone: the proxy client and the load. The load fetches the server's
# blob through the proxy; the hashes on both ends decide integrity.
set -u
# Offloads off so the wire sees real packet sizes (see wire/entrypoint.sh).
ethtool -K eth0 tso off gso off gro off 2> /dev/null || true
ip route add 10.77.2.0/24 via 10.77.1.2

xray run -c /wl/client.json > /out/client-xray.log 2>&1 &
i=0
while ! nc -z 127.0.0.1 1080 2> /dev/null; do
    i=$((i + 1)); [ $i -gt 100 ] && { echo "socks inbound never came up" > /out/client-error.txt; exit 1; }
    sleep 0.05
done

curl -sS --max-time "$TIMEOUT_S" --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:8080/blob -o /tmp/blob \
    -w '{"http_code":%{http_code},"size_download":%{size_download},"time_connect":%{time_connect},"time_starttransfer":%{time_starttransfer},"time_total":%{time_total},"speed_download":%{speed_download}}' \
    > /out/client-curl.json 2> /out/client-curl.err
echo $? > /out/client-curl.exit
[ -f /tmp/blob ] && sha256sum /tmp/blob | cut -d' ' -f1 > /out/client-blob.sha256
exit 0
