# WireGuard server on the lab port (UDP). Makes both key pairs and leaves
# the client's half in /shared. Forwards and masquerades the client's
# traffic to the target network. wg and iptables come from Alpine packages
# (the container needs the internet once).
set -eu
. /lab/recipe.env
command -v wg > /dev/null && command -v iptables > /dev/null || apk add --no-cache wireguard-tools-wg iptables > /dev/null
umask 077
s_priv=$(wg genkey); s_pub=$(echo "$s_priv" | wg pubkey)
c_priv=$(wg genkey); c_pub=$(echo "$c_priv" | wg pubkey)
echo "$s_priv" > /tmp/wg.key
ip link add wg0 type wireguard
wg set wg0 listen-port "$WL_SERVER_PORT" private-key /tmp/wg.key peer "$c_pub" allowed-ips 10.66.0.2/32
ip addr add 10.66.0.1/24 dev wg0
ip link set wg0 mtu "$WL_P_MTU" up
out=$(ip -o route get 10.77.3.10 | sed -E 's/.* dev ([^ ]+).*/\1/')
iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o "$out" -j MASQUERADE
printf '%s %s\n' "$c_priv" "$s_pub" > /shared/wg-client.tmp && mv /shared/wg-client.tmp /shared/wg-client
wg show wg0
