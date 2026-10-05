#!/bin/sh
# The wire zone: routes between the client and server networks, impairs
# traffic with netem and captures it on the client-side interface, which is
# where an ISP-level censor sits. c2s is captured as the client sent it, s2c
# after the impairments, as the client receives it.
set -eu

iface_in() { ip -o -4 addr show | awk -v net="$1" 'index($4, net) == 1 { print $2 }'; }
IF_C=$(iface_in 10.77.1.)
IF_S=$(iface_in 10.77.2.)
[ -n "$IF_C" ] && [ -n "$IF_S" ] || { echo "wire: interfaces not found" >&2; ip -o -4 addr show >&2; exit 1; }

# Offloads off: with them a veth carries 64 KB super-segments, and the
# capture would show packet sizes no real link ever carries.
for i in "$IF_C" "$IF_S"; do ethtool -K "$i" tso off gso off gro off 2> /dev/null || true; done

# Egress qdiscs: c2s leaves towards the server, s2c towards the client.
[ -n "${NETEM_C2S:-}" ] && tc qdisc replace dev "$IF_S" root netem $NETEM_C2S
[ -n "${NETEM_S2C:-}" ] && tc qdisc replace dev "$IF_C" root netem $NETEM_S2C
tc qdisc show dev "$IF_S" > /out/wire-qdisc.txt
tc qdisc show dev "$IF_C" >> /out/wire-qdisc.txt

# In a lab session the panel captures on demand through docker exec.
if [ "${WIRE_CAPTURE:-1}" = 0 ]; then
    echo "$IF_C $IF_S" > /tmp/ifaces
    touch /out/wire.ready
    trap 'exit 0' TERM INT
    while :; do sleep 3600 & wait $!; done
fi

# Captured to tmpfs and copied at the end: writing through to a Windows
# drive is slow enough that the kernel drops packets mid-transfer.
tcpdump -i "$IF_C" -B 65536 -s 0 -w /tmp/wire.pcap 'net 10.77.0.0/16' 2> /tmp/wire-tcpdump.log &
TCPDUMP=$!
finish() {
    kill -INT $TCPDUMP; wait $TCPDUMP
    cp /tmp/wire.pcap /out/wire.pcap; cp /tmp/wire-tcpdump.log /out/wire-tcpdump.log
    exit 0
}
trap finish TERM INT
# tcpdump writes the file header once it is listening.
while [ ! -s /tmp/wire.pcap ]; do sleep 0.05; done
touch /out/wire.ready
wait $TCPDUMP
