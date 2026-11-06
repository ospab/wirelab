# WireGuard client: wg0 with 10.66.0.2, the target network routed into it.
set -eu
. /lab/recipe.env
command -v wg > /dev/null || apk add --no-cache wireguard-tools-wg > /dev/null
i=0
while [ ! -s /shared/wg-client ]; do
    i=$((i + 1)); [ $i -gt 600 ] && { echo "no /shared/wg-client from the server after 60 s"; exit 1; }
    sleep 0.1
done
umask 077
set -- $(cat /shared/wg-client)
echo "$1" > /tmp/wg.key
ip link add wg0 type wireguard
ka=""
[ "$WL_P_KEEPALIVE" != 0 ] && ka="persistent-keepalive $WL_P_KEEPALIVE"
wg set wg0 private-key /tmp/wg.key peer "$2" endpoint "$WL_SERVER_ADDR:$WL_SERVER_PORT" allowed-ips 10.77.3.0/24 $ka
ip addr add 10.66.0.2/24 dev wg0
ip link set wg0 mtu "$WL_P_MTU" up
ip route add 10.77.3.0/24 dev wg0
wg show wg0
