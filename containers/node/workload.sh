#!/bin/sh
# Workloads, run in the client by `wirelab lab test`. Each one moves data to
# or from the target (through the protocol's proxy, or routed through the
# tunnel when the proxy is "-") and prints one JSON line with what it
# measured. Nothing here judges: the runner compares against thresholds.
#
#   probe  PROXY URL TIMEOUT_S              first successful GET
#   down   PROXY URL MAX_S                  download, sha256 against URL.sha256
#   up     PROXY BASE BYTES NAME MAX_S      upload with PUT to BASE/up/NAME
#   web    PROXY BASE ROUNDS PARALLEL MAX_S the 40 page objects, ROUNDS times
#   stream PROXY URL RATE SECONDS           steady download at RATE (curl units)
#   chat   PROXY URL COUNT INTERVAL_S       small requests at random intervals around INTERVAL_S
#   unauth ADDR PORT                        unauthenticated probes (CRTS CT-005)
set -u

px() { [ "$1" = "-" ] && echo "" || echo "-x $1"; }
now_ms() { echo $(( $(date +%s%N) / 1000000 )); }
jstr() { printf '"%s"' "$(printf '%s' "$1" | tr -d '\r' | tr '\n"\\' "  /" | cut -c1-300)"; }

cmd=$1; shift
case "$cmd" in
probe)
    proxy=$1 url=$2 timeout=$3
    start=$(now_ms) attempts=0 last=""
    while :; do
        attempts=$((attempts + 1))
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 $(px "$proxy") "$url" 2>/dev/null) && [ "$code" = 200 ] && {
            echo "{\"ok\":true,\"ms\":$(( $(now_ms) - start )),\"attempts\":$attempts}"
            exit 0
        }
        last="http ${code:-none}"
        [ $(( $(now_ms) - start )) -ge $((timeout * 1000)) ] && break
        sleep 0.5
    done
    echo "{\"ok\":false,\"ms\":$(( $(now_ms) - start )),\"attempts\":$attempts,\"error\":$(jstr "$last")}"
    ;;
down)
    proxy=$1 url=$2 max=$3
    expected=$(curl -s --max-time 20 $(px "$proxy") "$url.sha256" 2>/dev/null | cut -c1-64)
    sum=$(curl -sS --max-time "$max" $(px "$proxy") -w '%{stderr}\nWL %{http_code} %{size_download} %{time_total} %{time_starttransfer}\n' "$url" 2>/tmp/wl-down.err | sha256sum | cut -d' ' -f1)
    set -- $(grep '^WL ' /tmp/wl-down.err | tail -1)
    err=$(grep -v '^WL ' /tmp/wl-down.err | grep -v '^$' | tail -1)
    echo "{\"http\":$((${2:-0} + 0)),\"bytes\":${3:-0},\"seconds\":${4:-0},\"ttfb\":${5:-0},\"sha256\":\"$sum\",\"expected_sha256\":\"$expected\",\"error\":$(jstr "$err")}"
    ;;
up)
    proxy=$1 base=$2 bytes=$3 name=$4 max=$5
    head -c "$bytes" /dev/urandom > /tmp/wl-up
    sum=$(sha256sum /tmp/wl-up | cut -d' ' -f1)
    out=$(curl -sS --max-time "$max" $(px "$proxy") -T /tmp/wl-up -o /dev/null -w 'WL %{http_code} %{size_upload} %{time_total}' "$base/up/$name" 2>/tmp/wl-up.err)
    rm -f /tmp/wl-up
    set -- $out
    err=$(tail -1 /tmp/wl-up.err)
    echo "{\"http\":$((${2:-0} + 0)),\"bytes\":${3:-0},\"seconds\":${4:-0},\"sha256\":\"$sum\",\"error\":$(jstr "$err")}"
    ;;
web)
    proxy=$1 base=$2 rounds=$3 par=$4 max=$5
    cfg=/tmp/wl-web.cfg; : > $cfg
    r=1
    while [ $r -le "$rounds" ]; do
        i=1
        while [ $i -le 40 ]; do echo "url = \"$base/obj/$i?r=$r\"" >> $cfg; echo 'output = "/dev/null"' >> $cfg; i=$((i + 1)); done
        r=$((r + 1))
    done
    start=$(now_ms)
    curl -s -Z --parallel-max "$par" --max-time "$max" $(px "$proxy") -K $cfg -w '%{http_code} %{size_download} %{url}\n' > /tmp/wl-web.out 2>/dev/null
    ms=$(( $(now_ms) - start ))
    # Object i is 2000 + 700 i bytes (node.sh); anything else is damage.
    ok=$(awk '{ split($3, a, "/obj/"); split(a[2], b, "?"); if ($1 == 200 && $2 == 2000 + 700 * b[1]) n++ } END { print n + 0 }' /tmp/wl-web.out)
    echo "{\"objects\":$((rounds * 40)),\"ok\":$ok,\"ms\":$ms}"
    ;;
stream)
    proxy=$1 url=$2 rate=$3 secs=$4
    out=$(curl -s --max-time "$secs" --limit-rate "$rate" $(px "$proxy") -o /dev/null -w 'WL %{http_code} %{size_download} %{time_total} %{time_starttransfer}' "$url" 2>/dev/null)
    set -- $out
    echo "{\"http\":$((${2:-0} + 0)),\"bytes\":${3:-0},\"seconds\":${4:-0},\"ttfb\":${5:-0}}"
    ;;
chat)
    proxy=$1 url=$2 count=$3 interval=$4
    ms="" ok=0 n=0
    while [ $n -lt "$count" ]; do
        n=$((n + 1))
        t=$(curl -s -o /dev/null --max-time 10 $(px "$proxy") -w '%{http_code} %{time_total}' "$url?n=$n" 2>/dev/null)
        set -- $t
        if [ "${1:-0}" = 200 ]; then
            ok=$((ok + 1))
            ms="$ms${ms:+,}$(awk "BEGIN { printf \"%.1f\", $2 * 1000 }")"
        fi
        # Uniform in [0.5, 1.5] x interval: a person typing, not a timer, so
        # the periodicity CRTS CT-007 looks for is the protocol's, not ours.
        [ $n -lt "$count" ] && sleep "$(awk -v i="$interval" -v s="$n$$" 'BEGIN { srand(s); printf "%.3f", i * (0.5 + rand()) }')"
    done
    echo "{\"sent\":$count,\"ok\":$ok,\"ms\":[$ms]}"
    ;;
unauth)
    addr=$1 port=$2
    # Each class from its own source port, so the capture tells them apart.
    printf 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' "$addr" > /tmp/wl-http
    head -c 64 /dev/urandom > /tmp/wl-u64
    head -c 1200 /dev/urandom > /tmp/wl-u1200
    head -c 512 /dev/urandom > /tmp/wl-t512
    run() { # name proto sport file
        if [ "$2" = udp ]; then flag=-u; else flag=; fi
        got=$(nc $flag -w 3 -p "$3" "$addr" "$port" < "$4" 2>/dev/null | wc -c)
        printf '{"name":"%s","proto":"%s","sport":%s,"sent":%s,"recv":%s}' "$1" "$2" "$3" "$(wc -c < "$4")" "${got:-0}"
    }
    echo "{\"classes\":[$(run udp-random-64 udp 40101 /tmp/wl-u64),$(run udp-random-1200 udp 40102 /tmp/wl-u1200),$(run tcp-random-512 tcp 40103 /tmp/wl-t512),$(run tcp-http-get tcp 40104 /tmp/wl-http)]}"
    ;;
*)
    echo "{\"error\":\"unknown workload $cmd\"}"
    exit 2
    ;;
esac
